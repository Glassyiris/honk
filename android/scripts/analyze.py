#!/usr/bin/env python3
"""Joules per rail and wakeups per role thread for each measurement of a TunBench run.

Usage: uv run --project android/scripts android/scripts/analyze.py RUN_DIR [--max-gap-ms N]

RUN_DIR is what run.sh pulled: results.jsonl (one runner record per line) and trace.pftrace (a
Perfetto trace with android.power rails and sched events, trace clock BOOTTIME). Each record's
window [boottime_start_ns, boottime_end_ns] is cut out of the trace. That is the span of the
runner's CPU samples and counted bytes: the runner stops the traffic at boottime_cut_ns, drains
the bytes in flight and only then takes the end samples, so the drain is inside the window. The
output keeps boottime_cut_ns, scan_start_ns and scan_end_ns as the runner wrote them.
RUN_DIR/analysis.jsonl gets every record plus three objects:

  joules   {rail: J or null}: the energy each rail's cumulative counter gained; the rails are
           every counter track of type power_rails (named power.<RAIL>_uws, or power.rails.<name>
           for the rails trace_processor knows); two tracks of one name come out as <name>#<id>
  wakeups  {role: {"total": n, "threads": {tid: n}}}: runner threads made runnable from sleep
  invalid  {"status" | "window" | "joules.<rail>" | "wakeups" | "wakeups.<role>.<tid>": why that
           value is null}

A value is invalid, never guessed, when the trace cannot support it: the runner rejected the
measurement (every value is null), the rail has no samples, a window boundary lies outside them,
the counter went back, two samples are further apart than --max-gap-ms (default 1000), the trace
lost scheduler data anywhere (the loss counters are not timed, so this voids every window), or its
scheduler data does not span the window (as after the 2 GiB trace cap).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from bisect import bisect_right
from collections import Counter
from collections.abc import Sequence
from contextlib import closing
from functools import cached_property
from itertools import pairwise
from pathlib import Path
from typing import Any

from perfetto.trace_processor import TraceProcessor

BOOTTIME_CLOCK_ID = 6
NS_PER_MS = 1_000_000
UWS_TO_J = 1e-6
ROLES = ("engine", "relay", "generator", "sink")
# thread_state values of a thread that is not asleep: running, runnable after a yield, runnable
# because it was preempted (R+). Only an R that follows a sleep is a wakeup.
AWAKE = frozenset({"Running", "R", "R+"})
# Trace stats that count lost ftrace or trace-buffer data, besides those of severity data_loss.
LOSS_STATS = (
    "ftrace_cpu_overrun_delta",
    "ftrace_cpu_commit_overrun_delta",
    "ftrace_cpu_dropped_events_delta",
    "ftrace_cpu_has_data_loss",
    "traced_buf_chunks_overwritten",
    "traced_buf_chunks_discarded",
    "compact_sched_has_parse_errors",
    "ftrace_bundle_tokenizer_errors",
)

Samples = Sequence[tuple[int, float]]  # (ts ns, cumulative µWs), ascending by ts


class Invalid(ValueError):
    """A value the trace cannot support; the message says why."""


def _at(samples: Samples, k: int, t: int) -> float:
    """The counter at t, where samples[k] is the last sample at or before t: that sample when it
    lies at t (the last of several there), else interpolated towards the next one."""
    (t0, e0) = samples[k]
    if t0 == t:
        return e0
    t1, e1 = samples[k + 1]
    return e0 + (e1 - e0) * (t - t0) / (t1 - t0)


def window_joules(samples: Samples, start: int, end: int, max_gap: int) -> float:
    """Joules a cumulative µWs counter gained over [start, end] (ns): each boundary is
    interpolated between the samples around it, so the figure does not depend on where the
    samples fall. Raises Invalid when the counter cannot give a trustworthy figure."""
    if end <= start:
        raise Invalid("empty window")
    if not samples:
        raise Invalid("the rail has no samples")
    ts = [t for t, _ in samples]
    i, j = bisect_right(ts, start) - 1, bisect_right(ts, end) - 1
    if i < 0 or (ts[j] < end and j + 1 == len(samples)):
        raise Invalid("a window boundary lies outside the samples")
    last = j if ts[j] == end else j + 1
    for (t0, e0), (t1, e1) in pairwise(samples[i : last + 1]):
        if t1 - t0 > max_gap:
            raise Invalid(f"sample gap of {(t1 - t0) / NS_PER_MS:.0f} ms in the window")
        if e1 < e0:
            raise Invalid("the counter went back (reset)")
    return (_at(samples, j, end) - _at(samples, i, start)) * UWS_TO_J


def count_wakeups(rows: Sequence[tuple[int, str]], start: int, end: int) -> int:
    """Wakeups of one thread in [start, end): rows are its (ts, thread_state) in ascending ts,
    including the last one before the window. A wakeup ends a sleeping state: the next row is R,
    or Running when the waker ran before the sleeper's switch-out was recorded (no R row then; on a
    Pixel 10 Pro about a fifth of the sleeps end this way). R+ (preempted) and an R after running
    (a yield) are the scheduler's doing, not a wakeup."""
    count, prev = 0, None
    for ts, state in rows:
        woken = prev is not None and prev not in AWAKE and state in ("R", "Running")
        if woken and start <= ts < end:
            count += 1
        prev = state
    return count


def poll_interval_ns(rails: dict[str, Samples]) -> float | None:
    """Median spacing of the rail samples, or None if there are none."""
    gaps = [b[0] - a[0] for samples in rails.values() for a, b in pairwise(samples)]
    return statistics.median(gaps) if gaps else None


class Trace:
    """The few queries the analysis makes of one trace."""

    def __init__(self, path: Path):
        self._tp = TraceProcessor(trace=str(path))

    def close(self) -> None:
        self._tp.close()

    def clock_id(self) -> int | None:
        for row in self._tp.query(
            "SELECT int_value FROM metadata WHERE name = 'trace_time_clock_id'"
        ):
            return row.int_value
        return None

    def rails(self) -> dict[str, list[tuple[int, float]]]:
        """Every rail's cumulative energy counter (µWs) by rail name, a rail without samples
        included. Tracks that share a name are told apart as name#id."""
        tracks: dict[int, tuple[str, list[tuple[int, float]]]] = {}
        rows = self._tp.query(
            "SELECT t.id AS id, t.name AS name, c.ts AS ts, c.value AS value FROM counter_track t "
            "LEFT JOIN counter c ON c.track_id = t.id "
            "WHERE t.type = 'power_rails' ORDER BY t.name, t.id, c.ts"
        )
        for row in rows:
            name = row.name.removeprefix("power.").removesuffix("_uws")
            samples = tracks.setdefault(row.id, (name, []))[1]
            if row.ts is not None:
                samples.append((row.ts, row.value))
        shared = {n for n, c in Counter(name for name, _ in tracks.values()).items() if c > 1}
        return {f"{n}#{i}" if n in shared else n: s for i, (n, s) in tracks.items()}

    @cached_property
    def sched_loss(self) -> dict[str, int]:
        """The trace stats that report lost scheduler data, by name, summed over CPUs."""
        names = ",".join(f"'{n}'" for n in LOSS_STATS)
        rows = self._tp.query(
            "SELECT name, SUM(value) AS value FROM stats WHERE value > 0 "
            f"AND (severity = 'data_loss' OR name IN ({names})) GROUP BY name"
        )
        return {row.name: row.value for row in rows}

    @cached_property
    def sched_span(self) -> tuple[int, int] | None:
        """The first and the last context switch in the trace."""
        for row in self._tp.query("SELECT MIN(ts) AS lo, MAX(ts) AS hi FROM sched"):
            if row.lo is not None:
                return row.lo, row.hi
        return None

    def thread_states(
        self, tids: set[int], start: int, end: int
    ) -> dict[int, list[tuple[int, str]]]:
        """(ts, state) rows of each tid that overlap [start, end), plus the row before them."""
        if not tids:
            return {}
        rows = self._tp.query(
            "SELECT thread.tid AS tid, ts, state FROM thread_state JOIN thread USING (utid) "
            f"WHERE thread.tid IN ({','.join(str(int(t)) for t in tids)}) AND ts < {int(end)} "
            f"AND (dur < 0 OR ts + dur >= {int(start)}) ORDER BY thread.tid, ts"
        )
        states: dict[int, list[tuple[int, str]]] = {}
        for row in rows:
            states.setdefault(row.tid, []).append((row.ts, row.state))
        return states


def sched_gap(trace: Any, start: int, end: int) -> str | None:
    """Why the trace's scheduler data cannot give the wakeups in [start, end], or None."""
    if trace.sched_loss:
        lost = ", ".join(f"{k}={v}" for k, v in sorted(trace.sched_loss.items()))
        return f"the trace lost scheduler data: {lost}"
    span = trace.sched_span
    if span is None or span[0] > start or span[1] < end:
        return "the trace's scheduler data does not cover the window"
    return None


def analyze_record(
    rec: dict[str, Any], rails: dict[str, Samples], trace: Any, max_gap: int
) -> dict:
    """The record plus joules, wakeups and invalid; `trace` needs thread_states(), sched_loss
    and sched_span."""
    out = {**rec, "joules": {}, "wakeups": {}, "invalid": {}}
    roles = rec.get("roles") or {}
    tids = {role: [t["tid"] for t in roles[role]["threads"]] for role in ROLES if roles.get(role)}
    unknown = {role: {"total": None, "threads": {}} for role in tids}
    start, end = rec.get("boottime_start_ns"), rec.get("boottime_end_ns")
    if rec["status"] != "ok":
        out["invalid"]["status"] = f"{rec['status']}: {rec.get('reason')}"
    elif start is None or end is None:
        out["invalid"]["window"] = "the measurement has no window"
    if out["invalid"]:
        out["joules"], out["wakeups"] = dict.fromkeys(rails), unknown
        return out
    if not rails:
        out["invalid"]["joules"] = "the trace has no power rails"
    for rail, samples in rails.items():
        try:
            out["joules"][rail] = window_joules(samples, start, end, max_gap)
        except Invalid as e:
            out["joules"][rail] = None
            out["invalid"][f"joules.{rail}"] = str(e)
    gap = sched_gap(trace, start, end)
    if gap:
        out["wakeups"], out["invalid"]["wakeups"] = unknown, gap
        return out
    states = trace.thread_states({tid for ids in tids.values() for tid in ids}, start, end)
    for role, ids in tids.items():
        counts = {}
        for tid in ids:
            try:
                if tid in states:
                    counts[tid] = count_wakeups(states[tid], start, end)
                else:
                    raise Invalid("the trace has no scheduler data for it")
            except Invalid as e:
                out["invalid"][f"wakeups.{role}.{tid}"] = str(e)
        total = sum(counts.values()) if len(counts) == len(ids) else None
        out["wakeups"][role] = {"total": total, "threads": counts}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Joules and wakeups per TunBench measurement")
    ap.add_argument("run_dir", type=Path, help="run.sh's results directory")
    ap.add_argument("--max-gap-ms", type=float, default=1000, help="longest valid sample gap")
    args = ap.parse_args(argv)
    lines = (args.run_dir / "results.jsonl").read_text().splitlines()
    records = [json.loads(line) for line in lines if line.strip()]
    with closing(Trace(args.run_dir / "trace.pftrace")) as trace:
        if trace.clock_id() != BOOTTIME_CLOCK_ID:
            sys.exit("the trace clock is not BOOTTIME; the windows are CLOCK_BOOTTIME")
        rails = trace.rails()
        rows = [analyze_record(r, rails, trace, int(args.max_gap_ms * NS_PER_MS)) for r in records]
    poll = poll_interval_ns(rails)
    print(
        f"poll interval: {poll / NS_PER_MS:.0f} ms median over {len(rails)} rails"
        if poll
        else "poll interval: no rail samples in the trace"
    )
    out = args.run_dir / "analysis.jsonl"
    out.write_text("".join(json.dumps(row) + "\n" for row in rows))
    bad = sum(1 for row in rows if row["invalid"])
    print(f"{len(rows)} measurements, {bad} with invalid values: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
