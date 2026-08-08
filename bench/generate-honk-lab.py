#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run bench/generate-honk-lab.py --output-dir DIR --runs 1 --traffic udp
# 3. Or: chmod +x bench/generate-honk-lab.py && ./bench/generate-honk-lab.py --help
# ─────────────────
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Final

VARIANTS: Final = ("baseline-legacy", "candidate-legacy", "candidate-honk", "candidate-oracle")
TRAFFIC: Final = ("tcp", "udp", "dns")


def config(variant: str, cache_path: Path) -> str:
    policy = "min_moving_avg"
    node_filter = "name(keyword: 'relay-')"
    if variant == "candidate-honk":
        policy = "honk"
    if variant == "candidate-oracle":
        policy = "fixed(0)"
        node_filter = "name('relay-a')"
    return f"global {{ log_level: warn }}\nnode {{ relay-a: 'socks5://198.18.0.1:11080' relay-b: 'socks5://198.18.0.1:11081' }}\ngroup {{ lab {{ policy: {policy} filter: {node_filter} }} }}\nexperimental {{ cache_file {{ enabled: true path: '{cache_path}' cache_id: '' }} }}\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=1)
    args = parser.parse_args()
    if args.runs < 1 or args.runs > 5:
        parser.error("--runs must be in 1..5")
    states: list[dict[str, str | int]] = []
    for traffic in TRAFFIC:
        for run in range(1, args.runs + 1):
            for variant in VARIANTS:
                relative = Path("ab") / traffic / f"run-{run}" / variant
                root = args.output_dir / relative
                for directory in (root / "runtime", root / "cache"):
                    directory.mkdir(parents=True, exist_ok=True)
                cache_path = root / "cache" / "cache.db"
                (root / "config.dae").write_text(config(variant, cache_path.resolve()))
                states.append({"traffic": traffic, "run": run, "variant": variant, "relativePath": str(relative)})
    manifest = {"schema": 1, "variants": list(VARIANTS), "traffic": list(TRAFFIC), "states": states}
    (args.output_dir / "state-layout.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
