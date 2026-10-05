"""
``salt.jobs.published`` and ``salt.jobs.completed`` are counted in the master
parent process from the ``salt/job/`` events on the event bus, so each series
has exactly one owner regardless of ``worker_threads``.
"""

import asyncio

import pytest

import salt.utils.event
import salt.utils.metrics as metrics
from salt.master import Master, record_job_event_metrics


@pytest.fixture(autouse=True)
def _reset_metrics(monkeypatch):
    metrics.shutdown()
    monkeypatch.setattr(metrics, "_cached_opts", None)
    yield
    metrics.shutdown()


@pytest.fixture
def reader(monkeypatch):
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    rdr = InMemoryMetricReader()
    monkeypatch.setattr(metrics, "_build_readers", lambda _opts: [rdr])
    metrics.configure(
        {"metrics": {"enabled": True, "exporter": "console"}, "__role": "master"}
    )
    return rdr


def _points(rdr, name):
    out = {}
    data = rdr.get_metrics_data()
    if data is None:
        return out
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for m in sm.metrics:
                if m.name != name:
                    continue
                for dp in m.data.data_points:
                    key = tuple(sorted(dict(dp.attributes).items()))
                    out[key] = out.get(key, 0) + dp.value
    return out


@pytest.fixture
def master():
    # The handler only needs the class, not a started master.
    return Master.__new__(Master)


def _fire(master, tag, data):
    package = salt.utils.event.SaltEvent.pack(tag, data)
    asyncio.run(master._handle_metrics_event(package))


def test_new_event_counts_published(reader, master):
    for jid in ("1", "2"):
        _fire(master, f"salt/job/{jid}/new", {"jid": jid, "fun": "test.ping"})
    _fire(master, "salt/job/3/new", {"jid": "3", "fun": "test.echo"})
    assert _points(reader, "salt.jobs.published") == {
        (("fun", "test.ping"),): 2,
        (("fun", "test.echo"),): 1,
    }


def test_ret_event_counts_completed_with_success(reader, master):
    _fire(master, "salt/job/1/ret/m1", {"jid": "1", "id": "m1", "fun": "test.ping"})
    _fire(
        master,
        "salt/job/1/ret/m2",
        {"jid": "1", "id": "m2", "fun": "test.ping", "success": True},
    )
    _fire(
        master,
        "salt/job/1/ret/m3",
        {"jid": "1", "id": "m3", "fun": "test.ping", "success": False},
    )
    assert _points(reader, "salt.jobs.completed") == {
        (("fun", "test.ping"), ("success", "true")): 2,
        (("fun", "test.ping"), ("success", "false")): 1,
    }
    assert _points(reader, "salt.jobs.published") == {}


@pytest.mark.parametrize(
    "tag",
    [
        "salt/job/1/prog/m1/0",
        "salt/job/1/publish",
        "salt/auth",
        "salt/minion/m1/start",
        "salt/run/1/new",
        "state.sls",
        "salt/job/1/ret",  # no minion id
    ],
)
def test_other_events_are_ignored(reader, tag):
    record_job_event_metrics(tag, {"jid": "1", "fun": "x"})
    assert _points(reader, "salt.jobs.published") == {}
    assert _points(reader, "salt.jobs.completed") == {}


def test_peer_replicated_events_are_ignored(reader, master):
    # Cluster peers count their own jobs; the replica on our bus must not
    # be counted again.
    _fire(
        master,
        "salt/job/1/new",
        {"jid": "1", "fun": "test.ping", "__peer_id": "m2"},
    )
    _fire(
        master,
        "salt/job/1/ret/m1",
        {"jid": "1", "id": "m1", "fun": "test.ping", "__peer_id": "m2"},
    )
    assert _points(reader, "salt.jobs.published") == {}
    assert _points(reader, "salt.jobs.completed") == {}


def test_noop_when_metrics_disabled(master):
    metrics.configure({"metrics": {"enabled": False}, "__role": "master"})
    _fire(master, "salt/job/1/new", {"jid": "1", "fun": "test.ping"})
    _fire(master, "salt/job/1/ret/m1", {"jid": "1", "id": "m1", "fun": "test.ping"})


def test_metrics_failure_is_swallowed(master, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(metrics, "counter", boom)
    _fire(master, "salt/job/1/new", {"jid": "1", "fun": "test.ping"})


def test_metrics_event_loop_skipped_when_disabled(master):
    metrics.configure({"metrics": {"enabled": False}, "__role": "master"})
    # Returns immediately without touching the event bus (opts has no sock_dir).
    master.opts = {}
    asyncio.run(master._metrics_event_loop())
