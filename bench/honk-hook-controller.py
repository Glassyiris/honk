#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run bench/honk-hook-controller.py verify --token-file FILE --token TOKEN
# 3. Or: chmod +x bench/honk-hook-controller.py && ./bench/honk-hook-controller.py --help
# ─────────────────
from __future__ import annotations

import argparse
import hmac
from pathlib import Path
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--token-file", type=Path, required=True)
    verify.add_argument("--token", required=True)
    wait = sub.add_parser("wait")
    wait.add_argument("--state", type=Path, required=True)
    wait.add_argument("--timeout-ms", type=int, required=True)
    args = parser.parse_args()
    if args.action == "verify":
        expected = args.token_file.read_text().strip()
        return 0 if hmac.compare_digest(expected, args.token) else 1
    if args.action == "wait":
        deadline = time.monotonic() + args.timeout_ms / 1000
        while time.monotonic() < deadline:
            if args.state.is_file():
                return 0
            time.sleep(0.005)
        return 124
    raise AssertionError(args.action)


if __name__ == "__main__":
    raise SystemExit(main())
