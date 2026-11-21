"""run.sh against a stub adb on PATH that logs every call and answers the few the script reads."""

import json
import os
import subprocess
from pathlib import Path

import pytest
from google.protobuf import text_format
from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import TraceConfig

RUN_SH = Path(__file__).parent.parent / "run.sh"
STUB = r"""#!/bin/bash
ACTIVITY=dev.tunbench/.BenchActivity
echo "$*" >>"$STUB_DIR/log"
[ -f "$STUB_DIR/t0" ] || date +%s >"$STUB_DIR/t0"
age=$(($(date +%s) - $(cat "$STUB_DIR/t0")))
case "$*" in
  *"perfetto --background"*) cat >"$STUB_DIR/perfetto.cfg" && echo "${STUB_PERFETTO_PID:-4242}" ;;
  *"kill -0"*) [ -n "$STUB_PERFETTO_STUCK" ] || echo gone ;;
  *pgrep*) echo 4242 ;;
  "push "*) [ -z "$STUB_PUSH_FAILS" ] ;;
  *"getprop ro.build.id"*) echo TEST.1 ;;
  *"getprop ro.build.version.sdk_full"*) echo 37.2 ;;
  *"pm path"*) echo package:/data/app/base.apk ;;
  *sha256sum*) echo "abc123  /data/app/base.apk" ;;
  *"dumpsys power"*) printf 'mWakefulness=%s\n' "$STUB_WAKEFULNESS" ;;
  *"dumpsys display"*) printf '  Display State=%s\n' "${STUB_DISPLAY:-ON}" ;;
  *"dumpsys activity"*) echo "topResumedActivity=ActivityRecord{1 u0 $ACTIVITY t1}" ;;
  *pidof*) echo 123 ;;
  *"test -f"*) [ -n "$STUB_DONE" ] && [ "$age" -ge "${STUB_DONE_AFTER:-0}" ] ;;
  *"cat files/runs/"*"/done") echo "$STUB_DONE" ;;
  *"cat files/runs/"*"/results.jsonl") [ -n "$STUB_NO_RESULTS" ] || echo '{"seq":0}' ;;
  *"cat files/runs/"*) echo '{"seq":0}' ;;
  "pull "*) [ -z "$STUB_PULL_FAILS" ] && echo trace >"${!#}" ;;
  *"get global stay_on"*)  # STUB_STAYON before the start, STUB_STAYON_END after it
    if grep -q -- '--es plan' "$STUB_DIR/log"; then echo "${STUB_STAYON_END:-0}"
    else echo "${STUB_STAYON:-0}"; fi ;;
esac
"""
# 2 engines x 1 MTU x 2 repeats x (bulk 2 flows x (10 + 1 cooldown + 45 step) + idle (5 + 1 + 45)),
# plus the 120 s margin, is 772 s; the trace config adds 60 s.
PLAN = {
    "engines": ["hev", "honk"],
    "mtu": [8500],
    "repeat": 2,
    "cooldown_seconds": 1,
    "cases": [
        {"kind": "bulk", "dir": "up", "flows": [1, 2], "seconds": 10},
        {"kind": "idle", "seconds": 5},
    ],
}


@pytest.fixture
def phone(tmp_path):
    """Runs run.sh; returns (result, adb call log, results dir, trace config text)."""
    stub = tmp_path / "bin" / "adb"
    stub.parent.mkdir()
    stub.write_text(STUB)
    stub.chmod(0o755)

    def run(done, wakefulness="Awake", plan=PLAN, **extra):
        """Runs with `extra` as more environment (STUB_* switches, POLL, STEP, MARGIN)."""
        (tmp_path / "plan.json").write_text(json.dumps(plan))
        env = {
            **os.environ,
            "PATH": f"{stub.parent}:{os.environ['PATH']}",
            "STUB_DIR": str(tmp_path),
        }
        env |= {
            "STUB_DONE": done,
            "STUB_WAKEFULNESS": wakefulness,
            "RESULTS": str(tmp_path / "out"),
        }
        env |= {"POLL": "0", "GRACE": "0", "SCREEN_WAIT": "0"} | extra
        cmd = [str(RUN_SH), str(tmp_path / "plan.json"), "r1"]
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
        log = (tmp_path / "log").read_text()
        cfg = tmp_path / "perfetto.cfg"
        return result, log, tmp_path / "out" / "r1", cfg.read_text() if cfg.exists() else ""

    return run


def test_a_failed_run_still_stops_the_bench_and_perfetto(phone):
    result, log, _, _ = phone(done="", wakefulness="Asleep")
    assert result.returncode != 0
    assert "am start -n dev.tunbench/.BenchActivity --ez stop true --es run r1" in log
    assert "kill -TERM 4242" in log
    assert "stayon" not in log


def test_a_failure_before_the_start_sends_no_stop(phone):
    # nothing of this run is on the phone to stop
    result, log, _, _ = phone(done="", STUB_PUSH_FAILS="1")
    assert result.returncode != 0
    assert "--es run r1" not in log and "--ez stop true" not in log


def test_a_garbled_perfetto_answer_still_stops_perfetto(phone):
    result, log, _, _ = phone(done="ok", STUB_PERFETTO_PID="Connected to traced")
    assert result.returncode != 0
    assert "kill -TERM 4242" in log


def test_a_finished_run_is_pulled_and_leaves_no_stayon_behind(phone):
    result, log, out, cfg = phone(done="ok")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(out)
    assert (out / "done").read_text().strip() == "ok"
    assert (out / "results.jsonl").exists() and (out / "trace.pftrace").exists()
    meta = (out / "meta.txt").read_text()
    assert "build_id=TEST.1" in meta and "sdk_full=37.2" in meta and "apk_sha256=abc123" in meta
    assert "--ez stop true" not in log  # nothing to stop after a clean finish
    assert "stayon" not in log
    assert "stay_on_while_plugged_in_start=0" in meta and "stay_on_while_plugged_in_end=0" in meta
    after_pull = log.split("pull /data/misc/perfetto-traces/tunbench-r1.pftrace", 1)[1]
    assert "rm -f /data/misc/perfetto-traces/tunbench-r1.pftrace" in after_pull
    assert "run-as dev.tunbench cp /data/local/tmp/r1.json files/plans/r1.json" in log
    assert "--es plan r1.json --es run r1" in log
    assert "appops set dev.tunbench ACTIVATE_VPN allow" in log


def test_the_trace_config_parses_and_lasts_as_long_as_the_plan(phone):
    _, _, _, cfg = phone(done="ok")
    config = text_format.Parse(cfg, TraceConfig())  # a field the phone's perfetto lacks fails here
    assert config.duration_ms == (772 + 60) * 1000
    assert config.builtin_data_sources.primary_trace_clock == 6  # BOOTTIME
    ftrace = config.data_sources[0].config.ftrace_config
    assert list(ftrace.ftrace_events) == ["sched/sched_switch", "sched/sched_waking"]
    assert ftrace.compact_sched.enabled  # hours of sched events must stay small enough to analyze


def test_stay_on_set_at_the_start_refuses_to_wake_the_phone(phone):
    result, log, out, _ = phone(done="ok", STUB_STAYON="3")
    assert result.returncode != 0
    assert "stay_on_while_plugged_in_start=3" in (out / "meta.txt").read_text()
    assert "KEYCODE_WAKEUP" not in log and "--es plan" not in log


def test_stay_on_left_set_fails_the_run(phone):
    result, log, out, _ = phone(done="ok", STUB_STAYON_END="3")
    assert result.returncode != 0
    assert "stay_on_while_plugged_in_end=3" in (out / "meta.txt").read_text()
    assert "svc power" not in log  # the setting is only read, never changed


def test_a_failed_pull_keeps_the_phone_trace_and_fails_the_run(phone):
    result, log, out, _ = phone(done="ok", STUB_PULL_FAILS="1")
    assert result.returncode != 0
    assert "trace.pftrace" in result.stderr
    assert (out / "done").read_text().strip() == "ok"
    after_pull = log.split("pull /data/misc/perfetto-traces/tunbench-r1.pftrace", 1)[1]
    assert "rm -f /data/misc/perfetto-traces" not in after_pull


def test_an_empty_results_file_fails_the_run_and_is_named(phone):
    result, _, out, _ = phone(done="ok", STUB_NO_RESULTS="1")
    assert result.returncode != 0
    assert "results.jsonl" in result.stderr
    assert (out / "done").read_text().strip() == "ok"


def test_a_perfetto_that_does_not_exit_is_not_pulled(phone):
    result, log, _, _ = phone(done="ok", STUB_PERFETTO_STUCK="1")
    assert result.returncode != 0
    assert "pull " not in log


def test_a_done_file_after_the_deadline_does_not_count(phone):
    # one 1 s idle step, no STEP, a 2 s margin: the deadline is 3 s; done appears at 4 s
    plan = {**PLAN, "engines": ["hev"], "repeat": 1, "cooldown_seconds": 0}
    plan["cases"] = [{"kind": "idle", "seconds": 1}]
    env = {"STEP": "0", "MARGIN": "2", "POLL": "30", "STUB_DONE_AFTER": "4"}
    result, log, _, _ = phone(done="ok", plan=plan, **env)
    assert result.returncode != 0
    assert "--ez stop true" in log


def test_a_display_that_is_not_on_aborts_the_run(phone):
    # Android 17 reports the display state only in dumpsys display
    result, _, _, _ = phone(done="ok", STUB_DISPLAY="OFF")
    assert result.returncode != 0
    assert "Display State=OFF" in result.stderr
