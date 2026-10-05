"""
MWorkers buffer request/auth metrics locally and ship a summary to the master
parent, which applies it to the real instruments.
"""

import asyncio

import pytest

import salt.master
import salt.utils.event
import salt.utils.metrics as metrics


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    metrics.shutdown()
    monkeypatch.setattr(metrics, "_cached_opts", None)
    metrics.drain_worker_metrics()
    yield
    metrics.shutdown()
    metrics.drain_worker_metrics()


@pytest.fixture
def reader(monkeypatch):
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    rdr = InMemoryMetricReader()
    monkeypatch.setattr(metrics, "_build_readers", lambda _opts: [rdr])
    metrics.configure(
        {"metrics": {"enabled": True, "exporter": "console"}, "__role": "master"}
    )
    return rdr


def _metric(rdr, name):
    data = rdr.get_metrics_data()
    if data is None:
        return []
    return [
        m
        for rm in data.resource_metrics
        for sm in rm.scope_metrics
        for m in sm.metrics
        if m.name == name
    ]


def _counter_points(rdr, name):
    return {
        tuple(sorted(dict(dp.attributes).items())): dp.value
        for m in _metric(rdr, name)
        for dp in m.data.data_points
    }


def _hist_points(rdr, name):
    return {
        tuple(sorted(dict(dp.attributes).items())): dp
        for m in _metric(rdr, name)
        for dp in m.data.data_points
    }


def test_counters_aggregate_per_attribute_set(reader):
    for _ in range(3):
        metrics.worker_counter_add("salt.auth.attempts", 1, {"result": "success"})
    metrics.worker_counter_add("salt.auth.attempts", 1, {"result": "rejected"})
    # nothing reaches OTel until applied
    assert _counter_points(reader, "salt.auth.attempts") == {}
    summary = metrics.drain_worker_metrics()
    assert len(summary["counters"]) == 2
    # drained: second drain is empty
    assert metrics.drain_worker_metrics() is None
    metrics.apply_worker_summary(summary)
    assert _counter_points(reader, "salt.auth.attempts") == {
        (("result", "success"),): 3,
        (("result", "rejected"),): 1,
    }


def test_two_workers_sum_in_parent(reader):
    # Two flushes (two workers) for the same series add up.
    for n in (4, 6):
        metrics.worker_counter_add("salt.master.requests.handled", n, {"cmd": "ping"})
        metrics.apply_worker_summary(metrics.drain_worker_metrics())
    assert _counter_points(reader, "salt.master.requests.handled") == {
        (("cmd", "ping"),): 10
    }


def test_histogram_buffer_is_bounded_and_count_is_exact(reader):
    total = metrics.HISTOGRAM_SAMPLE_CAP * 5 + 7
    for i in range(total):
        metrics.worker_histogram_record(
            "salt.master.requests.duration", float(i), {"cmd": "ping"}
        )
    entry = list(metrics._agg_histograms.values())[0]
    assert len(entry[3]) == metrics.HISTOGRAM_SAMPLE_CAP  # bounded
    assert entry[2] == total  # exact count
    summary = metrics.drain_worker_metrics()
    metrics.apply_worker_summary(summary)
    dp = _hist_points(reader, "salt.master.requests.duration")[(("cmd", "ping"),)]
    assert dp.count == total
    # the sample is a subset of what was recorded
    assert 0 <= dp.min <= dp.max <= total


def test_histogram_small_sample_is_exact(reader):
    for v in (1.0, 2.0, 3.0):
        metrics.worker_histogram_record(
            "salt.master.requests.duration", v, {"cmd": "ping"}
        )
    metrics.apply_worker_summary(metrics.drain_worker_metrics())
    dp = _hist_points(reader, "salt.master.requests.duration")[(("cmd", "ping"),)]
    assert (dp.count, dp.sum) == (3, 6.0)


def test_histogram_uses_configured_boundaries(monkeypatch):
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    rdr = InMemoryMetricReader()
    monkeypatch.setattr(metrics, "_build_readers", lambda _opts: [rdr])
    metrics.configure(
        {
            "metrics": {
                "enabled": True,
                "exporter": "console",
                "histogram_boundaries": {"salt.master.requests.duration": [10, 20]},
            },
            "__role": "master",
        }
    )
    metrics.worker_histogram_record(
        "salt.master.requests.duration", 15.0, {"cmd": "ping"}
    )
    metrics.apply_worker_summary(metrics.drain_worker_metrics())
    dp = _hist_points(rdr, "salt.master.requests.duration")[(("cmd", "ping"),)]
    assert list(dp.explicit_bounds) == [10, 20]
    assert list(dp.bucket_counts) == [0, 1, 0]


def test_noop_when_disabled():
    metrics.configure({"metrics": {"enabled": False}, "__role": "master"})
    metrics.worker_counter_add("salt.auth.attempts", 1, {"result": "success"})
    metrics.worker_histogram_record("salt.master.requests.duration", 1.0, {"cmd": "x"})
    assert metrics.drain_worker_metrics() is None
    metrics.apply_worker_summary({"counters": [["salt.auth.attempts", "", {}, 1]]})


@pytest.mark.parametrize(
    "summary",
    [
        None,
        "x",
        {"counters": [["not.allowed", "", {}, 1]]},
        {"counters": [["salt.auth.attempts", "", {"jid": "1"}, 1]]},
        {"counters": [["salt.auth.attempts", "", {"result": "ok"}, -5]]},
        {"counters": [["salt.auth.attempts", "", {"result": "ok"}, "many"]]},
        {"counters": ["garbage"]},
        {
            "histograms": [
                ["salt.master.requests.duration", "", "ms", {"cmd": "x"}, 1, []]
            ]
        },
        {"histograms": [["salt.jobs.published", "", "ms", {}, 1, [1.0]]]},
    ],
)
def test_parent_rejects_bad_summaries(reader, summary):
    metrics.apply_worker_summary(summary)
    assert _counter_points(reader, "salt.auth.attempts") == {}
    assert _hist_points(reader, "salt.master.requests.duration") == {}
    assert _counter_points(reader, "salt.jobs.published") == {}


def test_parent_event_handler_applies_worker_summary(reader):
    metrics.worker_counter_add("salt.master.requests.handled", 2, {"cmd": "ping"})
    summary = metrics.drain_worker_metrics()
    package = salt.utils.event.SaltEvent.pack("salt/metrics/worker/MWorker-1", summary)
    master = salt.master.Master.__new__(salt.master.Master)
    asyncio.run(master._handle_metrics_event(package))
    assert _counter_points(reader, "salt.master.requests.handled") == {
        (("cmd", "ping"),): 2
    }


def test_parent_event_handler_skips_unrelated_events_without_unpacking(
    reader, monkeypatch
):
    def boom(*_a, **_k):
        raise AssertionError("must not unpack")

    monkeypatch.setattr(salt.utils.event.SaltEvent, "unpack", staticmethod(boom))
    package = salt.utils.event.SaltEvent.pack("minion/refresh/x", {"a": 1})
    master = salt.master.Master.__new__(salt.master.Master)
    asyncio.run(master._handle_metrics_event(package))


def test_worker_flush_fires_summary_on_bus(reader):
    fired = []

    class _Bus:
        def fire_event(self, data, tag, timeout=None):
            fired.append((tag, data))

    worker = salt.master.MWorker.__new__(salt.master.MWorker)
    worker._name = "MWorker-default-0"
    worker.opts = {"sock_dir": "/nonexistent"}
    worker._metrics_event = _Bus()
    # nothing buffered -> nothing fired
    worker._flush_worker_metrics()
    assert fired == []
    metrics.worker_counter_add("salt.auth.attempts", 1, {"result": "success"})
    worker._flush_worker_metrics()
    assert len(fired) == 1
    tag, data = fired[0]
    assert tag.startswith("salt/metrics/worker/")
    assert data["counters"][0][0] == "salt.auth.attempts"
    assert metrics.drain_worker_metrics() is None


def test_worker_flush_failure_is_swallowed(reader):
    class _Bus:
        def fire_event(self, *_a, **_k):
            raise OSError("bus down")

    worker = salt.master.MWorker.__new__(salt.master.MWorker)
    worker._name = "MWorker-default-0"
    worker.opts = {}
    worker._metrics_event = _Bus()
    metrics.worker_counter_add("salt.auth.attempts", 1, {"result": "success"})
    worker._flush_worker_metrics()  # must not raise


def test_auth_attempts_buffered_then_applied(reader):
    auth = salt.master.AuthFuncs.__new__(salt.master.AuthFuncs)
    auth.opts = {"master_async_mworker": False}
    auth._auth_impl_sync = lambda load, sign_messages=False, version=0: {
        "enc": "clear",
        "load": {"ret": True},
    }
    asyncio.run(auth._auth({"id": "m1"}))
    assert _counter_points(reader, "salt.auth.attempts") == {}
    metrics.apply_worker_summary(metrics.drain_worker_metrics())
    assert _counter_points(reader, "salt.auth.attempts") == {
        (("result", "success"),): 1
    }
