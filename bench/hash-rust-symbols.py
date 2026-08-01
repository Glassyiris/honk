#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run bench/hash-rust-symbols.py --manifest bench/protocol-surface-manifest.json
# 3. Or: chmod +x bench/hash-rust-symbols.py && ./bench/hash-rust-symbols.py --help
# ─────────────────
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


def extract(source: str, symbol: str) -> str:
    matches = list(re.finditer(rf"\bfn\s+{re.escape(symbol)}\s*(?:<[^{{;]*>)?\s*\(", source))
    if len(matches) != 1:
        raise SystemExit(f"symbol {symbol!r} has {len(matches)} definitions")
    start = matches[0].start()
    opening = source.find("{", matches[0].end())
    if opening < 0:
        raise SystemExit(f"symbol {symbol!r} has no body")
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_depth = 0
    index = opening
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            line_comment = current != "\n"
        elif block_depth:
            if current == "/" and following == "*":
                block_depth += 1
                index += 1
            elif current == "*" and following == "/":
                block_depth -= 1
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = ""
        elif current == "/" and following == "/":
            line_comment = True
            index += 1
        elif current == "/" and following == "*":
            block_depth = 1
            index += 1
        elif current in ('"', "'"):
            quote = current
        elif current == "{":
            depth += 1
        elif current == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
        index += 1
    raise SystemExit(f"symbol {symbol!r} body is unbalanced")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    handlers = manifest["handlers"]
    symbols = [symbol for handler in handlers for symbol in handler["symbols"]]
    if args.list:
        print(json.dumps({"handlers": len(handlers), "symbols": len(symbols)}, sort_keys=True))
        return 0
    failures: list[str] = []
    for item in symbols:
        path = args.root / item["path"]
        if path.is_symlink() or not path.is_file():
            failures.append(f"invalid source path: {path}")
            continue
        body = extract(path.read_text(encoding="utf-8"), item["symbol"])
        actual = hashlib.sha256(body.encode()).hexdigest()
        if actual != item["baselineBodySha256"]:
            failures.append(f"{item['path']}::{item['symbol']} expected {item['baselineBodySha256']} got {actual}")
    report = {"schema": 1, "handlers": len(handlers), "symbols": len(symbols), "ok": not failures, "failures": failures}
    print(json.dumps(report, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
