#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# ─── How to run ───
# python3 bench/run-honk-test-manifest.py list --manifest bench/honk-test-manifest.json --report REPORT

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from honk_harness.errors import HarnessError
from honk_harness.test_manifest import RunOptions, action_to_execute, run_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("list", "run"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    try:
        run_manifest(
            args.manifest,
            RunOptions(
                root=args.root.resolve(),
                report=args.report,
                target_dir=args.target_dir,
                timeout_seconds=args.timeout,
                execute=action_to_execute(args.action),
            ),
        )
    except (HarnessError, OSError) as error:
        print(f"run-honk-test-manifest: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
