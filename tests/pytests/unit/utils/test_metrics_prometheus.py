"""
Unit tests for the ``prometheus_client`` backend of salt.utils.metrics.
"""

import os
import socket
import sys
import urllib.request

import pytest

import salt.utils.metrics as metrics
import salt.utils.metrics_prometheus as backend

pytest.importorskip("prometheus_client")

pytestmark = [pytest.mark.skip_on_windows]


@pytest.fixture(autouse=True)
def _reset_metrics(monkeypatch):
    metrics.shutdown()
    monkeypatch.setattr(metrics, "_cached_opts", None)
    yield
    metrics.shutdown()


def _configure(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    metrics.configure(
        {
            "metrics": {
                "enabled": True,
                "exporter": "prometheus",
                "prometheus": {
                    "host": "127.0.0.1",
                    "port": port,
                    "multiproc_dir": str(tmp_path / "prom"),
                },
            },
            "__role": "master",
        }
    )
    return port


def _scrape(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as resp:
        return resp.read().decode()


@pytest.mark.parametrize(
    "name,unit,expected",
    [
        ("salt.jobs.completed", "", "salt_jobs_completed"),
        ("salt.job.duration", "ms", "salt_job_duration_milliseconds"),
        ("salt.process.open_fds", "{fd}", "salt_process_open_fds"),
        ("salt.x", "By", "salt_x_bytes"),
    ],
)
def test_metric_names_follow_the_otel_exporter(name, unit, expected):
    assert backend._metric_name(name, unit) == expected


def test_label_set_mismatch_does_not_raise(tmp_path):
    port = _configure(tmp_path)
    counter = metrics.counter("salt.test.mixed")
    counter.add(1, attributes={"cmd": "a"})
    # Missing and extra labels are mapped onto the first label set.
    counter.add(1)
    counter.add(1, attributes={"cmd": "a", "extra": "x"})
    body = _scrape(port)
    assert 'salt_test_mixed_total{cmd="a"} 2.0' in body
    assert 'salt_test_mixed_total{cmd=""} 1.0' in body


def test_same_name_returns_same_instrument(tmp_path):
    _configure(tmp_path)
    assert metrics.counter("salt.test.same") is metrics.counter("salt.test.same")


def test_stale_files_in_configured_directory_are_removed(tmp_path):
    directory = tmp_path / "prom"
    directory.mkdir()
    stale = directory / "counter_999999.db"
    stale.write_bytes(b"old")
    _configure(tmp_path)
    assert not stale.exists()


def test_prometheus_exporter_builds_no_otel_provider(tmp_path):
    _configure(tmp_path)
    assert metrics.get_meter() is None
    assert metrics._provider is None


def test_missing_prometheus_client_is_graceful(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "prometheus_client", None)
    monkeypatch.setattr(backend, "_pc", None)
    monkeypatch.setattr(backend, "_load_failed", False)
    metrics.configure(
        {
            "metrics": {"enabled": True, "exporter": "prometheus"},
            "__role": "master",
        }
    )
    assert metrics.is_enabled() is False
    assert metrics.counter("salt.test.none") is metrics._NOOP_COUNTER
    assert "PROMETHEUS_MULTIPROC_DIR" not in os.environ
