#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/honk-policy-lab-test.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_fail() {
	local name=$1
	shift
	if "$@" >"$TMP/$name.out" 2>"$TMP/$name.err"; then
		fail "$name unexpectedly passed"
	fi
}

help=$(bash "$ROOT/bench/honk-policy-lab.sh" --help)
[[ $help == *'--suite self-test'* && $help == *'--output-dir DIR'* ]] || fail 'help contract incomplete'
expect_fail missing-output bash "$ROOT/bench/honk-policy-lab.sh" --suite self-test
expect_fail relative-output bash "$ROOT/bench/honk-policy-lab.sh" --suite self-test --output-dir relative

bash "$ROOT/bench/honk-policy-lab.sh" --suite generate --output-dir "$TMP/generated"
python3 - "$TMP/generated/state-layout.json" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]).parent
layout = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert layout["variants"] == ["baseline-legacy", "candidate-legacy", "candidate-honk", "candidate-oracle"]
paths = [root / item["relativePath"] for item in layout["states"]]
assert len(paths) == len(set(paths)) == 12
assert all(path.is_dir() for path in paths)
PY

TOKEN_FILE="$TMP/token"
printf 'correct-token\n' >"$TOKEN_FILE"
expect_fail wrong-token python3 "$ROOT/bench/honk-hook-controller.py" verify --token-file "$TOKEN_FILE" --token wrong
expect_fail hook-timeout python3 "$ROOT/bench/honk-hook-controller.py" wait --state "$TMP/missing-state" --timeout-ms 20

printf 'honk policy lab CLI tests passed\n'
