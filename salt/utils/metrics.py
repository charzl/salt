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

The provider is rebuilt per-PID.  ``PeriodicExportingMetricReader`` does
not survive ``fork``, so every public entry point calls
:func:`_ensure_meter` which detects a PID change and rebuilds the
provider, reader and exporter in the child.

``exporter: prometheus`` does not use the OpenTelemetry SDK.  Counters and
histograms are ``prometheus_client`` metrics in multiprocess mode, so the
values of the master and all its workers are added up when
``/metrics`` is scraped (see :mod:`salt.utils.metrics_prometheus`).

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
      prometheus:
        host: 127.0.0.1               # localhost-bind by default
        port: 9464
        multiproc_dir: ""             # temp dir when empty; wiped at start
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
# The backend for ``metrics.exporter``; see :func:`_get_backend`.
_backend = None
_backend_lock = threading.Lock()


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


class Backend:
    """
    One way of recording and exporting metrics.

    :func:`configure` picks the backend for ``metrics.exporter`` and the
    public functions of this module delegate to it, so a new family of
    exporters only needs a new subclass.
    """

    def available(self):
        """Return True if the libraries this backend needs can be imported."""
        raise NotImplementedError

    def start(self, opts):
        """Prepare this process; return False if metrics cannot run here."""
        raise NotImplementedError

    def stop(self):
        """Flush and release what :meth:`start` set up."""
        raise NotImplementedError

    def counter(self, name, description, unit):
        raise NotImplementedError

    def histogram(self, name, description, unit):
        raise NotImplementedError

    def observable_gauge(self, name, callback, description, unit):
        raise NotImplementedError

    def meter(self):
        """Return the underlying OTel Meter; only the OTel backend has one."""
        return None


class OTelBackend(Backend):
    """
    The OpenTelemetry SDK with a push (OTLP) or console exporter.

    The provider is rebuilt per PID by :func:`_ensure_meter`.
    """

    def available(self):
        return _load_otel()

    def start(self, opts):
        if not _load_otel():
            log.warning(
                "metrics.enabled is true but opentelemetry is not installed; "
                "metrics remain disabled in this process."
            )
            return False
        log.info(
            "Enabling OpenTelemetry metrics (pid=%d, service=%s, exporter=%s, endpoint=%s)",
            os.getpid(),
            opts.get("service_name"),
            opts.get("exporter"),
            opts.get("endpoint") or "<default>",
        )
        _ensure_meter()
        return True

    def stop(self):
        global _provider, _meter, _last_pid  # pylint: disable=global-statement
        with _lock:
            provider = _provider
            _provider = None
            _meter = None
            _last_pid = None
        if provider is not None:
            try:
                provider.shutdown()
            except Exception:  # pylint: disable=broad-except
                log.debug("metrics provider shutdown raised", exc_info=True)

    def counter(self, name, description, unit):
        _ensure_meter()
        if _meter is None:
            return _NOOP_COUNTER
        return _meter.create_counter(name, description=description, unit=unit)

    def histogram(self, name, description, unit):
        _ensure_meter()
        if _meter is None:
            return _NOOP_HISTOGRAM
        return _meter.create_histogram(name, description=description, unit=unit)

    def observable_gauge(self, name, callback, description, unit):
        _ensure_meter()
        if _meter is None:
            return _NOOP_OBSERVABLE
        return _meter.create_observable_gauge(
            name, callbacks=[callback], description=description, unit=unit
        )

    def meter(self):
        _ensure_meter()
        return _meter


def _get_backend():
    """
    Return the backend for ``metrics.exporter``, creating it on first use.

    The same instance is returned from then on, also in forked children,
    which inherit it.  That is how a child knows the parent has already
    set things up.
    """
    global _backend  # pylint: disable=global-statement
    exporter = ((_cached_opts or {}).get("exporter") or "").lower()
    if exporter == "prometheus":
        # pylint: disable-next=import-outside-toplevel
        from salt.utils.metrics_prometheus import PrometheusBackend as factory
    else:
        factory = OTelBackend
    backend = _backend
    if backend.__class__ is not factory:
        with _backend_lock:
            if _backend.__class__ is not factory:
                _backend = factory()
            backend = _backend
    return backend


def is_enabled():
    """
    Return True if metrics are configured, enabled, and the libraries of
    the configured exporter can be imported.

    Structured so the disabled path never touches opentelemetry: when
    ``_cached_opts`` is unset or ``enabled`` is false (both true by
    default), no backend is created and the imports stay deferred.
    """
    if not _cached_opts or not _cached_opts.get("enabled"):
        return False
    return _get_backend().available()


def configure(opts):
    """
    Initialise metrics for this process.

    Safe to call multiple times; the provider is rebuilt only when the
    PID changes or the cached configuration is empty.  When metrics are
    disabled — or when the exporter's library is not installed — this is
    a cheap no-op that just caches the opts so subsequent calls in fork
    children can pick up the same setting.
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
    if not _atexit_registered:
        atexit.register(shutdown)
        _atexit_registered = True
    # The backend logs why it could not start, once.
    _get_backend().start(_cached_opts)


def shutdown():
    """Flush and tear down the active backend."""
    global _backend  # pylint: disable=global-statement
    backend, _backend = _backend, None
    if backend is not None:
        backend.stop()


def counter(name, *, description="", unit=""):
    """
    Create (or fetch) a Counter instrument.

    Returns :data:`_NOOP_COUNTER` when metrics are disabled so the caller
    can use ``.add(n, attributes=...)`` unconditionally.
    """
    if not is_enabled():
        return _NOOP_COUNTER
    return _get_backend().counter(name, description, unit)


def histogram(name, *, description="", unit="ms", boundaries=None):
    """
    Create (or fetch) a Histogram instrument.

    The ``boundaries`` argument is accepted but ignored at instrument
    creation time — bucket boundaries come from
    ``opts['metrics']['histogram_boundaries']``: the OTel SDK takes them
    from ``View``s attached to the ``MeterProvider`` (see
    :func:`_build_provider`), the Prometheus backend reads them directly.
    """
    if not is_enabled():
        return _NOOP_HISTOGRAM
    return _get_backend().histogram(name, description, unit)


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
    return _get_backend().observable_gauge(name, callback, description, unit)


def get_meter(name=_INSTRUMENTATION_NAME):
    """Return the underlying OTel Meter, or ``None`` when disabled.

    Useful as an escape hatch for instruments not covered by the
    convenience helpers above.  Always ``None`` with ``exporter: prometheus``.
    """
    if not is_enabled():
        return None
    return _get_backend().meter()


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

    Returns a list so a configuration can use more than one reader.  Today
    we return exactly one reader per call.  ``prometheus`` is not handled
    here: it does not use the OpenTelemetry SDK.
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
