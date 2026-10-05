# Salt Monitoring Environment

This environment sets up a Salt Master, two Minions, Prometheus, and cAdvisor for monitoring.

## Prerequisite

- Docker and Docker Compose (or Podman and podman-compose)

> **Note for Podman users:** If running in rootless mode, cAdvisor might require additional configuration to access host metrics. You may need to run Podman as root for full cAdvisor functionality, or use `podman stats` as an alternative.

## Usage

1. Start the environment:
   ```bash
   docker-compose up -d
   ```

2. Access the Salt Master:
   ```bash
   docker exec -it salt-master bash
   ```

3. Run a test command:
   ```bash
   salt '*' test.ping
   ```

4. Access Prometheus:
   Go to `http://localhost:9090`

5. Access cAdvisor:
   Go to `http://localhost:18081`

6. Access Grafana:
   Go to `http://localhost:13000`
   The "Salt Monitoring" dashboard is pre-provisioned.

## Monitoring for Memory Leaks

In Prometheus, you can use the following query to monitor memory usage of the salt-master container:

```promql
container_memory_usage_bytes{container_label_com_docker_compose_service="salt-master"}
```

Or more specifically for RSS:
```promql
container_memory_rss{container_label_com_docker_compose_service="salt-master"}
```

## Configuration

- `master.conf`: Salt Master configuration
- `minion.conf`: Salt Minion configuration (shared by both minions)
- `prometheus.yml`: Prometheus configuration
- `Dockerfile.salt`: Dockerfile for Salt components

## OpenTelemetry metrics

The master can expose its OpenTelemetry metrics (`salt_jobs_*`,
`salt_master_requests_*`, `salt_auth_attempts_total`) on port 9464.  They are
off by default, so `master.conf` has no `metrics:` block.  `SALT_METRICS`
picks an overlay that is mounted as `/etc/salt/master.d/metrics.conf`:

```bash
SALT_METRICS=on docker-compose up -d     # metrics.on.conf (prometheus exporter)
docker-compose up -d                     # metrics.off.conf (no metrics)
```

Prometheus scrapes `salt-master:9464` (job `salt-otel`), and Grafana has a
"Salt OTel Metrics" dashboard.  To compare memory with metrics on and off,
run the stress test once with each setting.

To check that the numbers add up, stop `stress_test.sh` (the master must be
otherwise idle) and run:

```bash
python3 check_otel_metrics.py -n 20
```

It sends N `test.ping` jobs to `salt-minion-1`, waits for the worker flush
(`worker_flush_interval_seconds`, default 10) and exits non-zero unless
published, completed and the `publish`/`_return` request counters and
duration counts all grew by exactly N.
