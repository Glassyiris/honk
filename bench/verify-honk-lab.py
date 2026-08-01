#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run bench/verify-honk-lab.py --output-dir DIR
# 3. Or: chmod +x bench/verify-honk-lab.py && ./bench/verify-honk-lab.py --help
# ─────────────────
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict[str, object]:  # noqa: OBJECT_OK
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    errors: list[str] = []
    for relay in ("a", "b"):
        path = args.output_dir / f"probe-{relay}.json"
        if not path.is_file() or path.is_symlink():
            errors.append(f"missing regular probe artifact: {path}")
            continue
        result = load(path)
        for protocol in ("tcp", "udp", "dns"):
            value = result.get(protocol)
            if not isinstance(value, dict) or value.get("ok") is not True:
                errors.append(f"{relay} {protocol} probe failed")
        udp = result.get("udp")
        if isinstance(udp, dict) and udp.get("relayMarker") != relay.upper():
            errors.append(f"{relay} relay source marker mismatch")
    layout_path = args.output_dir / "state-layout.json"
    if not layout_path.is_file():
        errors.append("state-layout.json missing")
    else:
        layout = load(layout_path)
        states = layout.get("states")
        if not isinstance(states, list) or len(states) != 12:
            errors.append("state layout must contain 12 isolated states")
        elif len({str(item.get("relativePath")) for item in states if isinstance(item, dict)}) != 12:
            errors.append("state layout paths are not isolated")
    cleanup = args.output_dir / "cleanup-receipt.json"
    if cleanup.exists():
        value = load(cleanup)
        if value.get("clean") is not True:
            errors.append("cleanup receipt is not clean")
    report = {"schema": 1, "ok": not errors, "errors": errors}
    (args.output_dir / "verification.json").write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    for error in errors:
        print(error)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
