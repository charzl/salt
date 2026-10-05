"""
OpenTelemetry metrics integration for Salt.

This module exposes a small, opinionated wrapper over the OpenTelemetry
Metrics SDK so that the rest of the codebase can create counters,
histograms and observable gauges unconditionally regardless of whether
metrics are enabled.

When ``opts['metrics']['enabled']`` is false (the default), every public
function short-circuits and instrument factories return no-op stubs.  No
``MeterProvider`` is initialised, no exporter is created, no background
thread is started, no listener is bound.

The provider is rebuilt per-PID.  ``PeriodicExportingMetricReader`` and
the Prometheus listener thread do not survive ``fork``, so every public
entry point calls :func:`_ensure_meter` which detects a PID change and
rebuilds the provider, reader and exporter in the child.

Configuration lives in ``opts['metrics']``::

    metrics:
      enabled: false
      exporter: otlp-http             # otlp-http | otlp-grpc | prometheus | console
      endpoint: ""                    # OTLP collector URL when applicable
      service_name: ""                # auto-derived when empty
      resource_attributes: {}
      insecure: true                  # gRPC TLS (ignored for non-grpc)
      headers: {}                     # OTLP auth headers
      export_interval_seconds: 60
      worker_flush_interval_seconds: 10  # MWorker -> master parent summaries
      prometheus:
        host: 127.0.0.1               # localhost-bind by default
        port: 9464
      histogram_boundaries:
        salt.job.duration: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000]
        salt.minion.exec.duration: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]

The default ``otlp-http`` exporter is pure-Python and ships in salt's
base requirements.  The ``otlp-grpc`` exporter is opt-in: install
``opentelemetry-exporter-otlp-proto-grpc`` separately to use it.

**Cardinality**: every instrument's labels must come from a bounded
domain.  Acceptable: ``fun`` (bounded by the salt module space),
``result`` (small enum), ``returner`` (configured returner names).
Unacceptable: ``minion_id``, ``jid``, ``user``.  Use those as trace
span attributes if you need them.
"""

import atexit
import logging
import os
import random
import threading
from types import SimpleNamespace

log = logging.getLogger(__name__)

_INSTRUMENTATION_NAME = "salt"

# Deferred OpenTelemetry state.  ``None`` means "we have not yet tried
# to import"; ``True`` / ``False`` are set by :func:`_load_otel` on
# first use.  ``_otel`` is a ``SimpleNamespace`` of the symbols we need
# from ``opentelemetry`` once the probe succeeds.
#
# Prior to this deferral the ``opentelemetry`` package was imported at
# module load, which cost ~15 MB per Python process.  Every salt daemon
# entry point transitively imports ``salt.utils.metrics`` (via
# ``salt.master`` / ``salt.minion``), so a ~15-process salt-master
# container was paying ~225 MB up front for a subsystem that defaults
# to disabled.  Deferring keeps that memory reserved for actual salt
# state on the vast majority of deployments where metrics are off.
_OTEL_AVAILABLE = None
_otel = None
_otel_load_lock = threading.Lock()


def _load_otel():
    """
    Attempt to import opentelemetry on first use.  Returns ``True`` if
    available.

    Only called from paths where metrics have already been confirmed
    enabled, so daemons with ``metrics.enabled = false`` (the default)
    never pay the per-process import cost.  Idempotent; the second call
    short-circuits on the memoised flag.
    """
    global _OTEL_AVAILABLE, _otel  # pylint: disable=global-statement
    if _OTEL_AVAILABLE is not None:
        return _OTEL_AVAILABLE
    with _otel_load_lock:
        if _OTEL_AVAILABLE is not None:
            return _OTEL_AVAILABLE
        try:
            # pylint: disable=import-outside-toplevel
            from opentelemetry import metrics as otel_metrics
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter as OTLPMetricExporterHTTP,
            )
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import (
                ConsoleMetricExporter,
                PeriodicExportingMetricReader,
            )
            from opentelemetry.sdk.metrics.view import (
                ExplicitBucketHistogramAggregation,
                View,
            )
            from opentelemetry.sdk.resources import Resource
        except ImportError:  # pragma: no cover - exercised when otel is absent
            _OTEL_AVAILABLE = False
            return False
        _otel = SimpleNamespace(
            otel_metrics=otel_metrics,
            OTLPMetricExporterHTTP=OTLPMetricExporterHTTP,
            MeterProvider=MeterProvider,
            PeriodicExportingMetricReader=PeriodicExportingMetricReader,
            ConsoleMetricExporter=ConsoleMetricExporter,
            ExplicitBucketHistogramAggregation=ExplicitBucketHistogramAggregation,
            View=View,
            Resource=Resource,
        )
        _OTEL_AVAILABLE = True
        return True


_lock = threading.Lock()
_last_pid = None
_provider = None
_meter = None
_cached_opts = None
_atexit_registered = False
# Track the Prometheus HTTP server thread so we can stop it across forks.
_prometheus_server_thread = None


class _NoopCounter:
    """Returned when metrics are disabled or opentelemetry is absent."""

    def add(self, amount, attributes=None):  # noqa: ARG002
        return None


class _NoopHistogram:
    def record(self, amount, attributes=None):  # noqa: ARG002
        return None


class _NoopObservableGauge:
    """The OTel API returns nothing useful from create_observable_gauge,
    but we keep a stand-in so call sites have a consistent return type."""


_NOOP_COUNTER = _NoopCounter()
_NOOP_HISTOGRAM = _NoopHistogram()
_NOOP_OBSERVABLE = _NoopObservableGauge()


def is_enabled():
    """
    Return True if metrics are configured, enabled, and opentelemetry
    can be imported.

    Structured so the disabled path never touches opentelemetry: when
    ``_cached_opts`` is unset or ``enabled`` is false (both true by
    default), :func:`_load_otel` is not called and the imports stay
    deferred.
    """
    if not _cached_opts or not _cached_opts.get("enabled"):
        return False
    return _load_otel()


def configure(opts):
    """
    Initialise metrics for this process.

    Safe to call multiple times; the provider is rebuilt only when the
    PID changes or the cached configuration is empty.  When metrics are
    disabled — or when opentelemetry is not installed — this is a cheap
    no-op that just caches the opts so subsequent calls in fork children
    can pick up the same setting.
    """
    global _cached_opts, _atexit_registered  # pylint: disable=global-statement
    metrics_opts = (opts or {}).get("metrics") or {}
    _cached_opts = dict(metrics_opts)
    _cached_opts.setdefault("service_name", _default_service_name(opts))
    if not _cached_opts.get("enabled"):
        log.debug(
            "metrics.configure called but metrics.enabled is false (pid=%d, service=%s)",
            os.getpid(),
            _cached_opts.get("service_name"),
        )
        return
    if not _load_otel():
        log.warning(
            "metrics.enabled is true but opentelemetry is not installed; "
            "metrics remain disabled in this process."
        )
        return
    if not _atexit_registered:
        atexit.register(shutdown)
        _atexit_registered = True
    log.info(
        "Enabling OpenTelemetry metrics (pid=%d, service=%s, exporter=%s, endpoint=%s)",
        os.getpid(),
        _cached_opts.get("service_name"),
        _cached_opts.get("exporter"),
        _cached_opts.get("endpoint") or "<default>",
    )
    _ensure_meter()


def shutdown():
    """Flush and tear down the active provider."""
    global _provider, _meter, _last_pid, _prometheus_server_thread
    with _lock:
        provider = _provider
        _provider = None
        _meter = None
        _last_pid = None
        # The prometheus_client http server thread is daemonic; we just
        # drop our reference.  It will exit with the process.
        _prometheus_server_thread = None
    if provider is not None:
        try:
            provider.shutdown()
        except Exception:  # pylint: disable=broad-except
            log.debug("metrics provider shutdown raised", exc_info=True)


def counter(name, *, description="", unit=""):
    """
    Create (or fetch) a Counter instrument.

    Returns :data:`_NOOP_COUNTER` when metrics are disabled so the caller
    can use ``.add(n, attributes=...)`` unconditionally.
    """
    if not is_enabled():
        return _NOOP_COUNTER
    _ensure_meter()
    if _meter is None:
        return _NOOP_COUNTER
    return _meter.create_counter(name, description=description, unit=unit)


def histogram(name, *, description="", unit="ms", boundaries=None):
    """
    Create (or fetch) a Histogram instrument.

    The ``boundaries`` argument is accepted but ignored at instrument
    creation time — the OTel SDK takes histogram bucket boundaries from
    ``View``s attached to the ``MeterProvider``.  Per-metric boundaries
    are wired up in :func:`_build_provider` from
    ``opts['metrics']['histogram_boundaries']``.
    """
    if not is_enabled():
        return _NOOP_HISTOGRAM
    _ensure_meter()
    if _meter is None:
        return _NOOP_HISTOGRAM
    return _meter.create_histogram(name, description=description, unit=unit)


def observable_gauge(name, callback, *, description="", unit=""):
    """
    Register an observable gauge whose value comes from ``callback``.

    ``callback`` must be a callable returning an iterable of
    ``opentelemetry.metrics.Observation`` (typical for OTel's API).  When
    metrics are disabled this returns :data:`_NOOP_OBSERVABLE` and the
    callback is never invoked.

    Observable gauges should be registered in the master parent process
    only — registering them in MWorker children would over-count.
    """
    if not is_enabled():
        return _NOOP_OBSERVABLE
    _ensure_meter()
    if _meter is None:
        return _NOOP_OBSERVABLE
    return _meter.create_observable_gauge(
        name, callbacks=[callback], description=description, unit=unit
    )


def get_meter(name=_INSTRUMENTATION_NAME):
    """Return the underlying OTel Meter, or ``None`` when disabled.

    Useful as an escape hatch for instruments not covered by the
    convenience helpers above.
    """
    if not is_enabled():
        return None
    _ensure_meter()
    return _meter


def _ensure_meter():
    global _last_pid  # pylint: disable=global-statement
    pid = os.getpid()
    if _last_pid == pid and _provider is not None:
        return
    with _lock:
        if _last_pid == pid and _provider is not None:
            return
        if _cached_opts is None or not _cached_opts.get("enabled"):
            return
        _build_provider()
        _last_pid = pid


def _build_provider():
    global _provider, _meter
    opts = _cached_opts or {}
    resource = _build_resource(opts)
    views = _build_views(opts)
    readers = _build_readers(opts)
    if not readers:
        log.warning(
            "metrics enabled but no reader could be built; instruments "
            "will record into the void."
        )
    provider = _otel.MeterProvider(
        resource=resource,
        metric_readers=readers,
        views=views,
    )
    _otel.otel_metrics.set_meter_provider(provider)
    _provider = provider
    _meter = provider.get_meter(_INSTRUMENTATION_NAME)


def _build_resource(opts):
    attrs = {"service.name": opts.get("service_name") or "salt"}
    extra = opts.get("resource_attributes") or {}
    if isinstance(extra, dict):
        attrs.update(extra)
    return _otel.Resource.create(attrs)


def _build_views(opts):
    """
    Build Views that map per-metric histogram bucket boundaries onto the
    matching instruments.  When no boundaries are configured we return an
    empty list and the SDK falls back to its default exponential buckets.
    """
    boundaries_map = opts.get("histogram_boundaries") or {}
    if not isinstance(boundaries_map, dict) or not boundaries_map:
        return []
    views = []
    for instrument_name, bounds in boundaries_map.items():
        if not isinstance(bounds, (list, tuple)) or not bounds:
            continue
        try:
            float_bounds = tuple(float(b) for b in bounds)
        except (TypeError, ValueError):
            log.warning(
                "Ignoring non-numeric histogram_boundaries for %s: %r",
                instrument_name,
                bounds,
            )
            continue
        views.append(
            _otel.View(
                instrument_name=instrument_name,
                aggregation=_otel.ExplicitBucketHistogramAggregation(
                    boundaries=float_bounds
                ),
            )
        )
    return views


def _build_readers(opts):
    """Build the metric reader(s) for the configured exporter.

    Returns a list because some configurations (notably ``prometheus``)
    naturally combine a pull reader with a push fallback.  Today we
    return exactly one reader per call.
    """
    name = (opts.get("exporter") or "otlp-http").lower()
    interval_seconds = float(opts.get("export_interval_seconds") or 60)
    endpoint = opts.get("endpoint") or None
    headers = opts.get("headers") or None
    insecure = opts.get("insecure", True)

    if name == "console":
        return [
            _otel.PeriodicExportingMetricReader(
                _otel.ConsoleMetricExporter(),
                export_interval_millis=int(interval_seconds * 1000),
            )
        ]

    if name == "otlp-http":
        kwargs = {}
        if endpoint:
            kwargs["endpoint"] = endpoint
        if headers:
            kwargs["headers"] = headers
        return [
            _otel.PeriodicExportingMetricReader(
                _otel.OTLPMetricExporterHTTP(**kwargs),
                export_interval_millis=int(interval_seconds * 1000),
            )
        ]

    if name == "otlp-grpc":
        try:
            # pylint: disable=import-outside-toplevel
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter as OTLPMetricExporterGRPC,
            )
        except ImportError:
            log.error(
                "opentelemetry-exporter-otlp-proto-grpc is not installed; "
                "either install it or set metrics.exporter to 'otlp-http' "
                "or 'prometheus'."
            )
            return []
        kwargs = {"insecure": bool(insecure)}
        if endpoint:
            kwargs["endpoint"] = endpoint
        if headers:
            kwargs["headers"] = headers
        return [
            _otel.PeriodicExportingMetricReader(
                OTLPMetricExporterGRPC(**kwargs),
                export_interval_millis=int(interval_seconds * 1000),
            )
        ]

    if name == "prometheus":
        try:
            from opentelemetry.exporter.prometheus import PrometheusMetricReader
            from prometheus_client import start_http_server
        except ImportError:
            log.error(
                "opentelemetry-exporter-prometheus is not installed; "
                "either install it or pick a different metrics.exporter."
            )
            return []
        prometheus_opts = opts.get("prometheus") or {}
        host = prometheus_opts.get("host", "127.0.0.1")
        port = int(prometheus_opts.get("port", 9464))
        global _prometheus_server_thread  # pylint: disable=global-statement
        try:
            # ``start_http_server`` is idempotent in the sense that calling
            # it twice in the same process raises ``OSError`` (port in use).
            # We track the thread we started so a fork child can re-bind.
            _prometheus_server_thread = start_http_server(port=port, addr=host)
        except OSError as exc:
            log.error(
                "Failed to bind Prometheus listener on %s:%d: %s",
                host,
                port,
                exc,
            )
            return []
        log.info("Prometheus /metrics listener bound on %s:%d", host, port)
        return [PrometheusMetricReader()]

    log.warning("Unknown metrics exporter %r; metrics will be a no-op", name)
    return []


def _default_service_name(opts):
    if not opts:
        return "salt"
    role = opts.get("__role")
    if role == "master":
        return "salt-master"
    if role == "minion":
        minion_id = opts.get("id") or ""
        return f"salt-minion-{minion_id}" if minion_id else "salt-minion"
    return "salt"


# ---------------------------------------------------------------------------
# Worker-side aggregation
#
# MWorker processes cannot expose metrics themselves (only the master parent
# binds the Prometheus port, and under OTLP identical series from N workers
# overwrite each other).  Instead, workers buffer their observations here and
# periodically ship a delta summary to the master parent over the event bus,
# where :func:`apply_worker_summary` replays it into the real instruments.
# ---------------------------------------------------------------------------

WORKER_SUMMARY_TAG = "salt/metrics/worker"
DEFAULT_WORKER_FLUSH_INTERVAL = 10.0
# Max raw histogram samples kept per (metric, attributes) between flushes.
HISTOGRAM_SAMPLE_CAP = 256

# Only these metrics (and attribute keys) are accepted by the parent; the
# event bus is writable by minions, so never trust the summary blindly.
_WORKER_METRICS = {
    "salt.master.requests.handled": {"cmd"},
    "salt.master.requests.duration": {"cmd"},
    "salt.auth.attempts": {"result"},
}

_agg_lock = threading.Lock()
_agg_counters = {}  # (name, attrs_tuple) -> [description, delta]
_agg_histograms = {}  # (name, attrs_tuple) -> [description, unit, count, values]


def worker_counter_add(name, amount, attributes, *, description=""):
    """
    Buffer a counter increment in this (worker) process.  No-op when
    metrics are disabled.
    """
    if not is_enabled():
        return
    key = (name, tuple(sorted(attributes.items())))
    with _agg_lock:
        entry = _agg_counters.get(key)
        if entry is None:
            _agg_counters[key] = [description, amount]
        else:
            entry[1] += amount


def worker_histogram_record(name, value, attributes, *, description="", unit="ms"):
    """
    Buffer a histogram observation in this (worker) process.  Raw values
    are kept in a bounded buffer (reservoir sampling beyond
    :data:`HISTOGRAM_SAMPLE_CAP`); the exact observation count is kept
    separately.  No-op when metrics are disabled.
    """
    if not is_enabled():
        return
    key = (name, tuple(sorted(attributes.items())))
    with _agg_lock:
        entry = _agg_histograms.get(key)
        if entry is None:
            _agg_histograms[key] = [description, unit, 1, [value]]
            return
        entry[2] += 1
        values = entry[3]
        if len(values) < HISTOGRAM_SAMPLE_CAP:
            values.append(value)
        else:
            # Algorithm R: each of the entry[2] observations is retained
            # with probability CAP / count.
            idx = random.randrange(entry[2])  # nosec - not security related
            if idx < HISTOGRAM_SAMPLE_CAP:
                values[idx] = value


def drain_worker_metrics():
    """
    Return and reset the buffered summary, or ``None`` if nothing is
    buffered.  The result is plain msgpack-able data.
    """
    with _agg_lock:
        if not _agg_counters and not _agg_histograms:
            return None
        counters = [
            [name, desc, dict(attrs), delta]
            for (name, attrs), (desc, delta) in _agg_counters.items()
        ]
        histograms = [
            [name, desc, unit, dict(attrs), count, values]
            for (name, attrs), (desc, unit, count, values) in _agg_histograms.items()
        ]
        _agg_counters.clear()
        _agg_histograms.clear()
    return {"counters": counters, "histograms": histograms}


def apply_worker_summary(summary):
    """
    Replay a summary produced by :func:`drain_worker_metrics` into the real
    instruments of this (parent) process.

    Histogram samples are weighted so the recorded observation count equals
    the exact count the worker saw; the sum is an estimate when the worker
    had to sample.
    """
    if not isinstance(summary, dict) or not is_enabled():
        return
    for item in summary.get("counters") or ():
        try:
            name, desc, attrs, delta = item
            if name not in _WORKER_METRICS or set(attrs) - _WORKER_METRICS[name]:
                continue
            if not isinstance(delta, (int, float)) or delta <= 0:
                continue
            counter(name, description=str(desc)).add(
                delta, attributes={k: str(v) for k, v in attrs.items()}
            )
        except (TypeError, ValueError, AttributeError):
            log.debug("Ignoring malformed worker counter %r", item)
    for item in summary.get("histograms") or ():
        try:
            name, desc, unit, attrs, count, values = item
            if name not in _WORKER_METRICS or set(attrs) - _WORKER_METRICS[name]:
                continue
            if not values or not isinstance(count, int) or count < len(values):
                continue
            hist = histogram(name, description=str(desc), unit=str(unit))
            attrs = {k: str(v) for k, v in attrs.items()}
            weight, extra = divmod(count, len(values))
            for i, value in enumerate(values):
                for _ in range(weight + (1 if i < extra else 0)):
                    hist.record(float(value), attributes=attrs)
        except (TypeError, ValueError, AttributeError):
            log.debug("Ignoring malformed worker histogram %r", item)
