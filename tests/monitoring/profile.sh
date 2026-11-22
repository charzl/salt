#!/bin/bash
# Profile one Salt process inside a stress test container.
#
# The nightly-stress-test.yml workflow copies this script into the container
# and starts it in the background when the ``profiler`` input is set.  It
# waits for the warm-up to pass, finds the process, runs the profiler for a
# fixed time and writes the results to $OUT.  The last thing it does is
# create $OUT/done, which the workflow waits for before copying $OUT out.
#
# Environment:
#   PROFILER         memray | austin | py-spy
#   TARGET           master (the master's main process), mworker
#                    (MWorker-default-0) or minion (the minion's main process)
#   DELAY            seconds to wait before profiling (default 600)
#   PROFILE_SECONDS  seconds to profile (default 600)
#   OUT              output directory (default /tmp/profile)
#
# A failing profiler never fails the stress test: this script only logs.

set -u

PROFILER="${PROFILER:?PROFILER is required}"
TARGET="${TARGET:-master}"
DELAY="${DELAY:-600}"
PROFILE_SECONDS="${PROFILE_SECONDS:-600}"
OUT="${OUT:-/tmp/profile}"

mkdir -p "$OUT"
LOG="$OUT/profile.log"

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG"
}

find_pid() {
    python3 - "$1" <<'PY'
import os
import sys

target = sys.argv[1]
me = os.getpid()
found = []
for name in os.listdir("/proc"):
    if not name.isdigit() or int(name) == me:
        continue
    try:
        with open(f"/proc/{name}/cmdline", "rb") as handle:
            cmdline = handle.read().replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        continue
    tokens = cmdline.split()
    if not tokens or cmdline.startswith(("sh -c", "/bin/sh -c", "/usr/bin/tini")):
        continue
    # Salt renames its processes with setproctitle, so the last word of the
    # command line is the role, e.g. ``MainProcess`` or ``MWorker-default-0``.
    if target == "master":
        match = "salt-master" in cmdline and tokens[-1] == "MainProcess"
    elif target == "mworker":
        match = "salt-master" in cmdline and tokens[-1] == "MWorker-default-0"
    elif target == "minion":
        match = "salt-minion" in cmdline
    else:
        match = False
    if match:
        found.append(int(name))
if found:
    print(min(found))
PY
}

rss_kb() {
    awk '/^VmRSS:/ {print $2}' "/proc/$1/status" 2>/dev/null
}

finish() {
    touch "$OUT/done"
    log "done"
}

log "profiler=$PROFILER target=$TARGET delay=${DELAY}s duration=${PROFILE_SECONDS}s python=$(python3 --version 2>&1)"
sleep "$DELAY"

PID="$(find_pid "$TARGET")"
if [ -z "$PID" ]; then
    log "no process found for target '$TARGET'; listing salt processes:"
    for cmdline in /proc/[0-9]*/cmdline; do
        tr '\0' ' ' < "$cmdline" 2>/dev/null | grep -E 'salt' | cut -c1-200 | tee -a "$LOG"
    done
    echo 1 > "$OUT/exit_code"
    finish
    exit 0
fi

log "pid=$PID cmdline=$(tr '\0' ' ' < "/proc/$PID/cmdline" | cut -c1-200)"
log "VmRSS before: $(rss_kb "$PID") kB"

case "$PROFILER" in
    memray)
        # ``attach`` returns at once; tracking stops by itself after --duration.
        # --native adds the C frames of pyzmq, libzmq and cryptography.
        memray attach --native --duration "$PROFILE_SECONDS" -o "$OUT/memray.bin" "$PID" >>"$LOG" 2>&1
        status=$?
        if [ "$status" -eq 0 ]; then
            sleep "$((PROFILE_SECONDS + 15))"
            if [ -s "$OUT/memray.bin" ]; then
                # What was allocated during the window and is still alive.
                memray flamegraph --leaks --force -o "$OUT/memray-leaks.html" "$OUT/memray.bin" >>"$LOG" 2>&1
                # Where memory was allocated, live or not.
                memray flamegraph --force -o "$OUT/memray-flamegraph.html" "$OUT/memray.bin" >>"$LOG" 2>&1
                memray stats "$OUT/memray.bin" >"$OUT/memray-stats.txt" 2>>"$LOG"
                memray summary "$OUT/memray.bin" >"$OUT/memray-summary.txt" 2>>"$LOG"
            else
                log "memray wrote no capture file"
                status=1
            fi
        fi
        ;;
    py-spy)
        # --subprocesses follows the workers forked by the master.
        py-spy record --pid "$PID" --duration "$PROFILE_SECONDS" --subprocesses \
            --format flamegraph --output "$OUT/pyspy-flamegraph.svg" >>"$LOG" 2>&1
        status=$?
        py-spy dump --pid "$PID" >"$OUT/pyspy-dump.txt" 2>>"$LOG"
        ;;
    austin)
        # -C follows child processes; -x is the exposure time in seconds.
        austin -C -x "$PROFILE_SECONDS" -p "$PID" -o "$OUT/austin.austin" >>"$LOG" 2>&1
        status=$?
        ;;
    *)
        log "unknown profiler '$PROFILER'"
        status=2
        ;;
esac

echo "$status" >"$OUT/exit_code"
log "profiler exit status: $status"
log "VmRSS after: $(rss_kb "$PID") kB"
ls -la "$OUT" >>"$LOG" 2>&1
finish
exit 0
