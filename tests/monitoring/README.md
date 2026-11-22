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

## Profiling

The stress test can tell you that a process grew, but not where. The image has
three profilers that attach to a running Salt process from the outside:

- `memray`: allocations with call stacks, including native frames. Its
  `--leaks` flamegraph shows what was allocated during the window and is still
  alive. Slow, so use it for manual runs.
- `py-spy`: sampling CPU profiler (flamegraph).
- `austin`: sampling CPU profiler. It writes a binary `.mojo` file, which the
  Austin VS Code extension opens.

In the `Nightly Stress Test` workflow, set `profiler` (`memray`, `austin` or
`py-spy`) and `profile_target` (`master`, `mworker` for `MWorker-default-0`, or
`minion`). The master's main process mostly supervises, so it allocates little:
use `mworker` to look for memory growth. `profile_minutes` is how long to profile. Profiling starts after the
10 minute warm-up, so it must fit in the run. It never changes pass or fail.

The run's summary shows what can be read inline: the memray statistics and top
allocators and the py-spy flamegraph. The HTML
flamegraphs (`memray-leaks.html` shows what was allocated in the window and is
still alive) and the raw captures are in the `profile` folder of the uploaded
artifact. Download it and open the HTML in a browser; GitHub serves HTML from
a branch as text, so it cannot be linked.

To do the same by hand:

```bash
export COMPOSE_FILE=docker-compose.yml:docker-compose.profiling.yml
docker compose up -d
docker cp profile.sh salt-master:/tmp/profile.sh
docker exec -e PROFILER=py-spy -e TARGET=master -e DELAY=0 \
    -e PROFILE_SECONDS=60 salt-master bash /tmp/profile.sh
docker cp salt-master:/tmp/profile ./profile
```

`docker-compose.profiling.yml` adds `SYS_PTRACE`, which attaching needs. The
default stress run does not use it.

## Configuration

- `master.conf`: Salt Master configuration
- `minion.conf`: Salt Minion configuration (shared by both minions)
- `prometheus.yml`: Prometheus configuration
- `Dockerfile.salt`: Dockerfile for Salt components
