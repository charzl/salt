#!/usr/bin/env python3
"""
Check that the master's OpenTelemetry metrics add up.

Sends N ``test.ping`` jobs to ONE minion through the master, waits for the
MWorker metrics to be flushed to the master parent, then checks on the
master's single Prometheus port (9464) that, compared to before the run:

* salt_jobs_published_total{fun="test.ping"}             grew by N
* salt_jobs_completed_total{fun="test.ping"}             grew by N
* salt_master_requests_handled_total{cmd="publish"}      grew by N
* salt_master_requests_handled_total{cmd="_return"}      grew by N
* salt_master_requests_duration_milliseconds_count for
  cmd="publish" and cmd="_return"                        grew by N

The master must be started with ``SALT_METRICS=on`` and should be otherwise
idle (stop stress_test.sh first), because the per-cmd request counters also
count other traffic.  Exits 0 on success, 1 on a mismatch, 2 if the metrics
cannot be read.

By default metrics are read with ``docker exec salt-master curl`` and jobs are
sent with ``docker exec salt-master salt``; use --metrics-url / --salt-cmd to
point at a master that is not in docker.
"""

import argparse
import re
import shlex
import subprocess
import sys
import time
import urllib.request

LINE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)")
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse(text):
    """Return {(name, frozenset(labels.items())): value}."""
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = LINE.match(line)
        if not m:
            continue
        labels = dict(LABEL.findall(m.group(2) or ""))
        out[(m.group(1), frozenset(labels.items()))] = float(m.group(3))
    return out


def value(samples, name, **labels):
    """Sum of samples of ``name`` whose labels include ``labels``."""
    want = set(labels.items())
    return sum(v for (n, lab), v in samples.items() if n == name and want <= set(lab))


def fetch(args):
    if args.metrics_url:
        with urllib.request.urlopen(args.metrics_url, timeout=10) as resp:
            return resp.read().decode()
    cmd = shlex.split(args.exec_prefix) + [
        "curl",
        "-sf",
        "http://localhost:9464/metrics",
    ]
    return subprocess.run(
        cmd, check=True, capture_output=True, text=True, timeout=30
    ).stdout


def checks(samples):
    ping = {"fun": "test.ping"}
    return {
        'salt_jobs_published_total{fun="test.ping"}': value(
            samples, "salt_jobs_published_total", **ping
        ),
        'salt_jobs_completed_total{fun="test.ping"}': value(
            samples, "salt_jobs_completed_total", **ping
        ),
        'salt_master_requests_handled_total{cmd="publish"}': value(
            samples, "salt_master_requests_handled_total", cmd="publish"
        ),
        'salt_master_requests_handled_total{cmd="_return"}': value(
            samples, "salt_master_requests_handled_total", cmd="_return"
        ),
        'salt_master_requests_duration_milliseconds_count{cmd="publish"}': value(
            samples, "salt_master_requests_duration_milliseconds_count", cmd="publish"
        ),
        'salt_master_requests_duration_milliseconds_count{cmd="_return"}': value(
            samples, "salt_master_requests_duration_milliseconds_count", cmd="_return"
        ),
    }


def deltas(before, after):
    return {k: after[k] - before[k] for k in before}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    ap.add_argument("-n", type=int, default=20, help="number of test.ping jobs")
    ap.add_argument("--target", default="salt-minion-1", help="single minion to ping")
    ap.add_argument("--exec-prefix", default="docker exec salt-master")
    ap.add_argument(
        "--salt-cmd",
        help="command that runs the salt CLI (default: '<exec-prefix> salt')",
    )
    ap.add_argument("--metrics-url", help="read metrics from this URL instead")
    ap.add_argument(
        "--flush-interval",
        type=float,
        default=10.0,
        help="metrics.worker_flush_interval_seconds of the master",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="max seconds to wait for the counts to settle "
        "(default: 3 x flush interval + 10)",
    )
    args = ap.parse_args(argv)
    timeout = args.timeout or 3 * args.flush_interval + 10
    salt_cmd = shlex.split(args.salt_cmd or f"{args.exec_prefix} salt")

    try:
        before = checks(parse(fetch(args)))
    except Exception as exc:  # pylint: disable=broad-except
        print(f"cannot read metrics: {exc}", file=sys.stderr)
        return 2

    print(f"sending {args.n} x test.ping to {args.target} ...")
    for _ in range(args.n):
        subprocess.run(
            salt_cmd + [args.target, "test.ping"],
            check=True,
            capture_output=True,
            timeout=60,
        )

    # Request metrics reach the parent on the workers' next flush.  Poll
    # until every delta equals N (or we give up) instead of sleeping blindly.
    deadline = time.time() + timeout
    time.sleep(min(args.flush_interval, 2))
    while True:
        try:
            after = checks(parse(fetch(args)))
        except Exception as exc:  # pylint: disable=broad-except
            print(f"cannot read metrics: {exc}", file=sys.stderr)
            return 2
        diff = deltas(before, after)
        if all(d == args.n for d in diff.values()) or time.time() > deadline:
            break
        time.sleep(2)

    ok = True
    print(f"{'metric':<72} {'delta':>8} {'expected':>8}")
    for name, delta in diff.items():
        status = "ok" if delta == args.n else "MISMATCH"
        ok &= delta == args.n
        print(f"{name:<72} {delta:>8g} {args.n:>8}  {status}")
    if not ok:
        print(
            "FAILED: some deltas differ from N (is the master idle and "
            "started with SALT_METRICS=on?)",
            file=sys.stderr,
        )
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
