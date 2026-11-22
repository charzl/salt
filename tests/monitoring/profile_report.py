#!/usr/bin/env python3
# pylint: disable=resource-leakage
"""
Turn the raw output of a profiler into a short report in plain words.

The flamegraphs and capture files of py-spy and memray are not easy to read
if you have not used the tools.  This script writes a markdown report that
says what the profiler saw and how to read it, and that the workflow puts at
the top of the run summary.

    profile_report.py py-spy <flamegraph.svg>   [--seconds N] [--rate N]
    profile_report.py memray <memray.bin>       [--rss-before KB] [--rss-after KB]

It only reads files and prints markdown.  It never fails the caller: an
error is written into the report instead.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import traceback
from collections import defaultdict

TOP = 12

# Own time spent in these is a thread that is waiting, not working.
WAITING = (
    "select",
    "poll",
    "epoll",
    "sleep",
    "wait",
    "acquire",
    "recv",
    "accept",
)


def md_escape(text):
    return text.replace("|", "\\|").replace("`", "'")


def short_location(name):
    """Keep the function and the last two parts of the file path."""
    match = re.match(r"^(.*?) \((.*):(\d+)\)$", name)
    if not match:
        return name
    func, path, line = match.groups()
    parts = path.replace("\\", "/").split("/")
    return f"{func} ({'/'.join(parts[-2:])}:{line})"


def is_salt(name):
    return "salt/" in name or "salt-master:" in name


# ---------------------------------------------------------------------------
# py-spy
# ---------------------------------------------------------------------------

FRAME = re.compile(
    r"<g><title>(?P<title>.*?) \((?P<samples>[\d,]+) samples?, [\d.]+%\)</title>"
    r'<rect x="[^"]*" y="(?P<y>\d+)" width="[^"]*" height="\d+" fill="[^"]*" '
    r'fg:x="(?P<fx>\d+)" fg:w="(?P<fw>\d+)"'
)


def parse_pyspy(path):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    total = re.search(r'id="frames"[^>]*total_samples="(\d+)"', text)
    frames = []
    for match in FRAME.finditer(text):
        frames.append(
            {
                "name": html.unescape(match.group("title")),
                "y": int(match.group("y")),
                "x": int(match.group("fx")),
                "w": int(match.group("fw")),
            }
        )
    return (int(total.group(1)) if total else 0), frames


def own_times(frames):
    """Own samples of every frame: its width less that of its children."""
    rows = defaultdict(list)
    for frame in frames:
        rows[frame["y"]].append(frame)
    row_ys = sorted(rows)
    for frame in frames:
        frame["own"] = frame["w"]
    for frame in frames:
        # py-spy's flamegraph has the root at the top and a frame's callees on
        # the row below it (the next larger y).
        below = [y for y in row_ys if y > frame["y"]]
        if not below:
            continue
        for child in rows[min(below)]:
            if (
                frame["x"] <= child["x"]
                and child["x"] + child["w"] <= frame["x"] + frame["w"]
            ):
                frame["own"] -= child["w"]


def cumulative_times(frames):
    """Samples under each function name, counting a name once per stack."""
    totals = defaultdict(int)
    for frame in frames:
        nested = any(
            other["name"] == frame["name"]
            and other["y"] < frame["y"]
            and other["x"] <= frame["x"]
            and frame["x"] + frame["w"] <= other["x"] + other["w"]
            for other in frames
        )
        if not nested:
            totals[frame["name"]] += frame["w"]
    return totals


def pyspy_report(path, seconds, rate):
    total, frames = parse_pyspy(path)
    out = ["## py-spy: where the CPU time goes", ""]
    if not total or not frames:
        out.append("The flamegraph has no samples, so there is nothing to report.")
        return out
    own_times(frames)

    by_own = defaultdict(int)
    for frame in frames:
        by_own[frame["name"]] += max(frame["own"], 0)
    by_total = cumulative_times(frames)
    # The root and the process frames are labels, not code.
    for label in [k for k in by_own if k == "all" or k.startswith("process ")]:
        by_own.pop(label, None)
        by_total.pop(label, None)

    def pct(value):
        return f"{100.0 * value / total:.1f}%"

    waiting = sum(v for k, v in by_own.items() if any(w in k.lower() for w in WAITING))
    salt_own = sum(v for k, v in by_own.items() if is_salt(k))

    out.append(
        f"py-spy took **{total:,} samples**"
        + (
            f" over {seconds // 60 if seconds >= 120 else seconds} "
            f"{'minutes' if seconds >= 120 else 'seconds'} at {rate} a second"
            if seconds and rate
            else ""
        )
        + ", across the process and the processes it started. "
        "Each sample is a snapshot of what every running thread was doing."
    )
    out.append("")
    out.append(
        f"- **{pct(waiting)}** of the samples are in calls that wait "
        "(select, poll, sleep, lock, queue). That is a thread with nothing to do, "
        "not work."
    )
    out.append(f"- **{pct(salt_own)}** of the samples are in Salt's own code.")
    out.append("")

    out.append("### Where the time is spent (own time)")
    out.append("")
    out.append(
        "Own time is the time in the function itself, not in what it calls. "
        "A function with a high share here is the hot spot."
    )
    out.append("")
    out.append("| Share | Function |")
    out.append("| ---: | --- |")
    for name, value in sorted(by_own.items(), key=lambda item: -item[1])[:TOP]:
        out.append(f"| {pct(value)} | `{md_escape(short_location(name))}` |")
    out.append("")

    salt_total = {k: v for k, v in by_total.items() if is_salt(k)}
    if salt_total:
        out.append("### Salt functions that are on the stack most (cumulative time)")
        out.append("")
        out.append(
            "Cumulative time includes everything the function calls. A high share "
            "means the time is spent somewhere below this function."
        )
        out.append("")
        out.append("| Share | Function |")
        out.append("| ---: | --- |")
        for name, value in sorted(salt_total.items(), key=lambda item: -item[1])[:TOP]:
            out.append(f"| {pct(value)} | `{md_escape(short_location(name))}` |")
        out.append("")

    out.append("### How to read this")
    out.append("")
    out.append(
        "- Look at the first table. If one non-waiting function has a share much "
        "larger than the rest, that is where to look for a CPU hot spot."
    )
    out.append(
        "- If most of the time is waiting, the process was mostly idle while it "
        "was profiled, and there is no CPU problem in it."
    )
    out.append(
        "- To see the stacks, open the flamegraph above: the wider a box, the more "
        "samples; each box sits on the function that called it."
    )
    return out


# ---------------------------------------------------------------------------
# memray
# ---------------------------------------------------------------------------


def readable(size):
    value = float(size)
    for unit in ("B", "kB", "MB", "GB"):
        if abs(value) < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} GB"


def frame_text(frame):
    func, path, line = frame[0], frame[1], frame[2]
    parts = (path or "").replace("\\", "/").split("/")
    return f"{func} ({'/'.join(parts[-2:])}:{line})"


def python_frame(frames):
    """The nearest Python frame, leaf first (the native frames come before it)."""
    for frame in frames:
        if (frame[1] or "").endswith(".py"):
            return frame_text(frame)
    return None


def salt_caller(frames):
    """The nearest frame in Salt's own code, leaf first."""
    for frame in frames:
        if "/salt/" in (frame[1] or "") and "/ext/" not in (frame[1] or ""):
            return frame_text(frame)
    return None


def memray_report(path, rss_before, rss_after):
    from memray import FileReader  # pylint: disable=import-outside-toplevel

    reader = FileReader(path, report_progress=False)
    meta = reader.metadata
    out = ["## memray: what allocated memory", ""]

    total_allocations = getattr(meta, "total_allocations", None)
    peak = getattr(meta, "peak_memory", None)

    leaked = list(reader.get_leaked_allocation_records(merge_threads=True))
    live_bytes = sum(record.size for record in leaked)
    live_count = sum(record.n_allocations for record in leaked)

    out.append(
        "memray recorded every allocation of the process while it was attached"
        + (f": **{total_allocations:,} allocations**" if total_allocations else "")
        + (f", peak **{readable(peak)}**" if peak else "")
        + "."
    )
    out.append("")
    out.append(
        f"- **{readable(live_bytes)}** in **{live_count:,} allocations** were made "
        "while attached and were **still alive when it detached**. This is the "
        "memory that grew and was not given back."
    )
    if rss_before and rss_after:
        grew = rss_after - rss_before
        out.append(
            f"- The process size (RSS) went from {readable(rss_before * 1024)} to "
            f"{readable(rss_after * 1024)} ({'+' if grew >= 0 else '-'}{readable(abs(grew) * 1024)}) "
            "over the same time."
        )
        if grew > 0 and live_bytes < grew / 4:
            out.append(
                "- The live allocations explain only a small part of the growth. The "
                "rest is memory memray does not count as an allocation, for example "
                "pages shared with other processes that became private, "
                "fragmentation, or memory taken by C code that does not use malloc."
            )
    out.append("")

    if not leaked:
        out.append("Nothing allocated in the window was still alive at the end.")
        return out

    by_site = defaultdict(lambda: [0, 0])
    by_salt = defaultdict(lambda: [0, 0])
    for record in leaked:
        try:
            frames = record.hybrid_stack_trace(max_stacks=24)
        except Exception:  # pylint: disable=broad-except
            frames = record.stack_trace(max_stacks=24)
        if not frames:
            continue
        site = python_frame(frames) or frame_text(frames[0])
        by_site[site][0] += record.size
        by_site[site][1] += record.n_allocations
        caller = salt_caller(frames)
        if caller:
            by_salt[caller][0] += record.size
            by_salt[caller][1] += record.n_allocations

    def table(title, note, data):
        out.append(f"### {title}")
        out.append("")
        out.append(note)
        out.append("")
        out.append("| Still alive | Allocations | Where |")
        out.append("| ---: | ---: | --- |")
        for site, (size, count) in sorted(data.items(), key=lambda item: -item[1][0])[
            :TOP
        ]:
            out.append(f"| {readable(size)} | {count:,} | `{md_escape(site)}` |")
        out.append("")

    table(
        "Where the live memory was allocated",
        "The nearest Python function on the stack of the allocation. It is "
        "often a library, for example a socket or a string function.",
        by_site,
    )
    if by_salt:
        table(
            "Which Salt code asked for it",
            "The nearest function in Salt's own code on the stack of those "
            "allocations. This is the place to start reading.",
            by_salt,
        )

    out.append("### How to read this")
    out.append("")
    out.append(
        "- A site with many allocations that are all still alive, and a size that "
        "keeps growing from run to run, is a leak candidate."
    )
    out.append(
        "- A cache or a buffer that fills once and then stays the same size shows "
        "up here as well, but it does not grow: compare two runs or a longer "
        "profile before calling it a leak."
    )
    out.append(
        "- For the full call stacks open `memray-leaks.html` from the artifact in "
        "a browser. The widest boxes are the biggest live allocations."
    )
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("py-spy", "memray"))
    parser.add_argument("path")
    parser.add_argument("--seconds", type=int, default=0)
    parser.add_argument("--rate", type=int, default=0)
    parser.add_argument("--rss-before", type=int, default=0, help="kB")
    parser.add_argument("--rss-after", type=int, default=0, help="kB")
    args = parser.parse_args()
    try:
        if args.tool == "py-spy":
            lines = pyspy_report(args.path, args.seconds, args.rate)
        else:
            lines = memray_report(args.path, args.rss_before, args.rss_after)
    except Exception:  # pylint: disable=broad-except
        lines = [
            f"## {args.tool}: report failed",
            "",
            "The raw files are in the artifact. Why the report failed:",
            "",
            "```",
            traceback.format_exc().strip(),
            "```",
        ]
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
