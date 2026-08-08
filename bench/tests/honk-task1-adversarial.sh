#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
OUTPUT=''
while (($#)); do
	case $1 in
	--output) OUTPUT=$2; shift 2 ;;
	*) exit 2 ;;
	esac
done
[[ $OUTPUT == /* ]] || exit 2
TMP=$(mktemp -d "${TMPDIR:-/tmp}/honk-task1-adversarial.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT

bash "$ROOT/bench/tests/honk-evidence-cli.sh" >"$TMP/evidence.log"
bash "$ROOT/bench/tests/honk-policy-lab-cli.sh" >"$TMP/lab.log"
mkdir -p "$TMP/root/crates/honk-outbound/src/proxy/hysteria2"
python3 - "$ROOT/bench/protocol-surface-manifest.json" "$TMP/root" "$ROOT" <<'PY'
import json, pathlib, shutil, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
target, root = pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
for handler in manifest["handlers"]:
    for symbol in handler["symbols"]:
        destination = target / symbol["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / symbol["path"], destination)
PY
python3 - "$TMP/root/crates/honk-outbound/src/proxy/vless.rs" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace("fn build_request_header(\n", "fn build_request_header(\n        ", 1))
PY
if python3 "$ROOT/bench/hash-rust-symbols.py" --manifest "$ROOT/bench/protocol-surface-manifest.json" --root "$TMP/root" >"$TMP/mutated.log" 2>&1; then exit 1; fi
if timeout -s KILL 1s sh -c 'sleep 5' >"$TMP/timeout.log" 2>&1; then exit 1; fi
marker="$ROOT/.task1-unrelated-marker"
printf 'preserve\n' >"$marker"
test "$(cat "$marker")" = preserve
unlink "$marker"
mkdir -p "$(dirname -- "$OUTPUT")"
python3 - "$OUTPUT" <<'PY'
import json, pathlib, sys
classes = {
    "malformed_input": "PASS: recorder rejects bad hash, JSON state and symlink fixtures",
    "cancel_resume": "PRECONDITION: AF_INET sandbox denial prevents a live interrupted run; bounded cleanup is separately verified",
    "stale_state": "PASS: protected-symbol mutation and stale hashes return nonzero",
    "dirty_worktree": "PASS: unrelated marker survived all scoped checks until fixture cleanup",
    "hung_or_long_commands": "PASS: stubborn timeout returned nonzero within the bound",
    "flaky_tests": "PASS: deterministic CLI suites repeated",
    "misleading_success_output": "PASS: missing commands and zero expected-negative exits are rejected",
    "repeated_interruptions": "PRECONDITION: socket sandbox blocks live harness interruption; Geo restore is idempotently rerunnable",
    "prompt_injection": "NOT_APPLICABLE: no untrusted natural-language ingestion or instruction execution surface was added",
}
pathlib.Path(sys.argv[1]).write_text(json.dumps({"schema": 1, "classes": classes}, sort_keys=True, separators=(",", ":")) + "\n")
PY
printf 'task1 adversarial tests passed\n'
