#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
PLAN="$ROOT/.omo/plans/udp-group-latency-stability-optimization.md"
PLAN_SHA=e36273bf07db8bf7bb4aac68c42d235461078de6aae9dae58dbc06530fe2f5de
TMP=$(mktemp -d "${TMPDIR:-/tmp}/honk-evidence-test.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_fail() {
	local name=$1
	shift
	if "$@" >"$TMP/$name.out" 2>"$TMP/$name.err"; then
		fail "$name unexpectedly passed"
	fi
}

python3 "$ROOT/bench/record-honk-evidence.py" self-test
python3 "$ROOT/bench/run-recorded.py" --self-test

ATTEMPT="$TMP/attempt"
mkdir -p "$ATTEMPT"
cp -- "$PLAN" "$ATTEMPT/reviewed-plan.md"
python3 "$ROOT/bench/record-honk-evidence.py" approve \
  --attempt-dir "$ATTEMPT" --reviewed-plan-sha "$PLAN_SHA"
python3 "$ROOT/bench/record-honk-evidence.py" begin --task 1 \
  --attempt-dir "$ATTEMPT" --reviewed-plan-sha "$PLAN_SHA" \
  --pre-task-commit "$(git -C "$ROOT" rev-parse HEAD)"
TASK_DIR="$ATTEMPT/task-1-udp-group-latency-stability-optimization"
python3 "$ROOT/bench/run-recorded.py" --log "$TASK_DIR/commands.jsonl" -- /bin/sh -c 'printf recorded'
printf '[{"path":"%s","kind":"external"}]\n' "$TASK_DIR/commands.jsonl" >"$TASK_DIR/artifacts.json"
python3 "$ROOT/bench/record-honk-evidence.py" end --task 1 \
  --attempt-dir "$ATTEMPT" --reviewed-plan-sha "$PLAN_SHA" \
  --execution-commit "$(git -C "$ROOT" rev-parse HEAD)" --commit-created no \
  --artifacts-json "$TASK_DIR/artifacts.json"
python3 - "$TASK_DIR/receipt.json" "$PLAN_SHA" <<'PY'
import hashlib, json, pathlib, sys
receipt = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert receipt["reviewedPlanSha256"] == sys.argv[2]
assert receipt["commands"][0]["exitStatus"] == 0
assert len(receipt["commands"][0]["stdoutSha256"]) == 64
assert hashlib.sha256(pathlib.Path(receipt["artifacts"][0]["path"]).read_bytes()).hexdigest() == receipt["artifacts"][0]["sha256"]
PY

ln -s "$PLAN" "$TMP/plan-link"
expect_fail plan-symlink env HONK_REVIEWED_PLAN_PATH="$TMP/plan-link" python3 "$ROOT/bench/record-honk-evidence.py" approve --attempt-dir "$TMP/bad-link" --reviewed-plan-sha "$PLAN_SHA"
expect_fail plan-hash python3 "$ROOT/bench/record-honk-evidence.py" approve --attempt-dir "$TMP/bad-hash" --reviewed-plan-sha "${PLAN_SHA%?}0"
cp -R "$ATTEMPT" "$TMP/missing-command"
rm -f "$TMP/missing-command/task-1-udp-group-latency-stability-optimization/commands.jsonl"
expect_fail missing-command python3 "$ROOT/bench/record-honk-evidence.py" end --task 1 --attempt-dir "$TMP/missing-command" --reviewed-plan-sha "$PLAN_SHA" --execution-commit "$(git -C "$ROOT" rev-parse HEAD)" --commit-created no --artifacts-json "$TMP/missing-command/task-1-udp-group-latency-stability-optimization/artifacts.json"

printf 'honk evidence CLI tests passed\n'
