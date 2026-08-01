#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly: uv run bench/run-recorded.py --log commands.jsonl -- COMMAND
# 3. Or: chmod +x bench/run-recorded.py && ./bench/run-recorded.py --help
# ─────────────────
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from typing import Final

SCHEMA: Final = 1


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: dict[str, int | str | bool | list[str]]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def execute(log_path: Path, argv: list[str], expected_negative: bool) -> int:
    if not argv:
        raise SystemExit("run-recorded: command is required after --")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.is_symlink():
        raise SystemExit(f"run-recorded: log must not be a symlink: {log_path}")
    sequence = sum(1 for _ in log_path.open(encoding="utf-8")) + 1 if log_path.exists() else 1
    stem = log_path.parent / f"command-{sequence:04d}"
    started = datetime.now(UTC).isoformat()
    result = subprocess.run(argv, check=False, capture_output=True)
    ended = datetime.now(UTC).isoformat()
    stdout_path = stem.with_suffix(".stdout")
    stderr_path = stem.with_suffix(".stderr")
    stdout_path.write_bytes(result.stdout)
    stderr_path.write_bytes(result.stderr)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    record: dict[str, int | str | bool | list[str]] = {
        "schema": SCHEMA,
        "sequence": sequence,
        "argv": argv,
        "startedAt": started,
        "endedAt": ended,
        "exitStatus": result.returncode,
        "expectedNegative": expected_negative,
        "stdoutPath": str(stdout_path.resolve()),
        "stdoutSha256": digest(result.stdout),
        "stderrPath": str(stderr_path.resolve()),
        "stderrSha256": digest(result.stderr),
    }
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "ab") as handle:
        handle.write(canonical(record))
        handle.flush()
        os.fsync(handle.fileno())
    return result.returncode


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="honk-run-recorded-") as raw:
        log = Path(raw) / "commands.jsonl"
        exit_status = execute(log, ["/bin/sh", "-c", "printf ok"], False)
        row = json.loads(log.read_text())
        if exit_status != 0 or row["stdoutSha256"] != digest(b"ok"):
            return 1
    print("run-recorded self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute one argv and append a hash-bound JSONL record.")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--expected-negative", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.log is None:
        parser.error("--log is required")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    return execute(args.log.resolve(), command, args.expected_negative)


if __name__ == "__main__":
    raise SystemExit(main())
