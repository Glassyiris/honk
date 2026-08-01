#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run bench/run-honk-causal-ablation.py --output FILE
# 3. Or: chmod +x bench/run-honk-causal-ablation.py && ./bench/run-honk-causal-ablation.py --help
# ─────────────────
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import statistics
import time
from typing import Callable


def measured(action: Callable[[int], None], count: int) -> list[int]:
    values: list[int] = []
    for index in range(count):
        started = time.perf_counter_ns()
        action(index)
        values.append(time.perf_counter_ns() - started)
    return values


def p95(values: list[int]) -> int:
    return sorted(values)[(len(values) * 95 + 99) // 100 - 1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    activity_a: dict[int, int] = {}
    activity_b: dict[int, int] = {}

    def write_activity(index: int) -> None:
        activity_a[index % 64] = index
        activity_b[index % 64] = index

    activity = measured(write_activity, 20000)
    nodes = list(range(8192))
    victims = set(nodes[::100])

    def sparse_removal(_index: int) -> None:
        tuple(node for node in nodes if node in victims)

    removal = measured(sparse_removal, 200)
    removals = list(range(4096))

    def cleanup_items(_index: int) -> None:
        tuple(removals)

    cleanup = measured(cleanup_items, 200)

    def serial(_index: int) -> None:
        time.sleep(0.002)
        time.sleep(0.002)

    def overlap(_index: int) -> None:
        with ThreadPoolExecutor(max_workers=2) as executor:
            tuple(executor.map(time.sleep, (0.002, 0.002)))

    serial_values = measured(serial, 20)
    overlap_values = measured(overlap, 20)
    output = {
        "schema": 1,
        "materialityOnly": True,
        "clock": "perf_counter_ns",
        "tasks": {
            "6": {"scenario": "two per-flow activity map writes", "samples": len(activity), "p95Ns": p95(activity), "medianNs": int(statistics.median(activity)), "predicate": "selection_cpu>=2pct_or_p95>=5us", "thresholdMet": p95(activity) >= 5000, "task1Decision": "NO_CHANGE"},
            "7": {"scenario": "8192 endpoints and 1 percent sparse removal", "samples": len(removal), "p95Ns": p95(removal), "predicate": "p95>=100us", "thresholdMet": p95(removal) >= 100000, "task1Decision": "ELIGIBLE_FOR_TASK18_RELATIVE_GATE" if p95(removal) >= 100000 else "NO_CHANGE"},
            "8": {"scenario": "4096 lossless removal consumer items", "samples": len(cleanup), "p95Ns": p95(cleanup), "predicate": "guard_overhead>=100us_or_cleanup_cpu>=5pct", "thresholdMet": p95(cleanup) >= 100000, "task1Decision": "NO_CHANGE"},
            "9": {"scenario": "two independently blocking cold preparation stages", "samples": 20, "serialP95Ns": p95(serial_values), "overlapP95Ns": p95(overlap_values), "overlapDeltaNs": p95(serial_values) - p95(overlap_values), "predicate": "overlap_delta_p95>=100us", "thresholdMet": p95(serial_values) - p95(overlap_values) >= 100000, "task1Decision": "ELIGIBLE_FOR_TASK18_RELATIVE_GATE" if p95(serial_values) - p95(overlap_values) >= 100000 else "NO_CHANGE"},
        },
        "prohibition": "not a final baseline/candidate relative performance claim",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
