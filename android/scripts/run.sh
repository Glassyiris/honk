#!/bin/bash
# Runs a TunBench plan on the phone over adb, with a Perfetto trace of the power rails and the
# scheduler running beside it, and pulls the results.
#
# Usage: run.sh PLAN.json [RUN_ID]
#   RUN_ID (A-Z a-z 0-9 . _ -) defaults to <date>-<time>-<plan name>. Prints the results directory,
#   $RESULTS/RUN_ID: plan.json, results.jsonl and done (written by the app), trace.pftrace,
#   meta.txt (APK, plan, build, thermal, stay_on_while_plugged_in) and screen.txt (wakefulness,
#   display, brightness).
#   Then: uv run --project android/scripts android/scripts/analyze.py <that directory>
#
# Contract with the app (BenchActivity, dev.tunbench):
#   start  am start -n dev.tunbench/.BenchActivity --es plan <name in files/plans/> --es run RUN_ID
#   stop   am start -n dev.tunbench/.BenchActivity --ez stop true --es run RUN_ID
#          (cancels RUN_ID only if it is the run in progress)
#   When Bench.run returns the app has written files/runs/RUN_ID/{plan.json,results.jsonl,done}
#   (done holds "ok" or why the run ended). The app cannot read /data/local/tmp, so the plan is
#   pushed there and copied into files/plans/ with run-as; consent is appops ACTIVATE_VPN allow.
#
# The phone must stay interactive with the panel black while it measures: BenchActivity keeps the
# screen on (FLAG_KEEP_SCREEN_ON) only while it is in front. A few seconds after the start,
# mWakefulness=Awake, the display ON and BenchActivity the resumed top activity must hold, else the
# run aborts. The script never changes stay_on_while_plugged_in; it records the setting at the
# start and the end, refuses to wake the phone if it is not 0 at the start and fails if it is not
# 0 at the end. Whatever ends the run, short of SIGKILL, the exit trap sends the stop intent if
# this run's start was sent and the app has not finished, stops Perfetto and waits for it to exit,
# saves what the app wrote and pulls the trace, deleting the phone's copy only after the pull. A
# failed stop fails the run, and so does any of plan.json, a non-empty results.jsonl, done and the
# trace not pulled. INT and TERM do not cut the trap short, and each of its adb calls has a time
# limit.
#
# Environment:
#   ADB     the adb command (default adb; ADB="adb -s SERIAL")
#   RESULTS results root (default android/results)
#   POLL    seconds between checks for the done file (default 30; every check is an adb call that
#           the phone sees, so keep it long)
#   MARGIN  seconds added to the plan's worst-case duration for the deadline (default 120)
#   STEP    seconds of setup and teardown assumed per measurement (default 45)
#   SCREEN_WAIT  seconds the screen may take to come up after the start (default 10)
#   GRACE   seconds the exit trap waits for the app to answer the stop intent (default 20)
set -euo pipefail

[ $# -ge 1 ] && [ $# -le 2 ] || {
  echo "usage: run.sh PLAN.json [RUN_ID]" >&2
  exit 2
}
plan=$1
[ -f "$plan" ] || {
  echo "no such plan: $plan" >&2
  exit 2
}
here=$(cd "$(dirname "$0")" && pwd)
run_id=${2:-$(date +%Y%m%d-%H%M%S)-$(basename "$plan" .json)}
case $run_id in
*[!A-Za-z0-9._-]*)
  echo "RUN_ID may use only A-Z a-z 0-9 . _ -" >&2
  exit 2
  ;;
esac
read -ra adb_cmd <<<"${ADB:-adb}"
# adb runs in timeout's own process group, where reading the terminal would stop it.
exec </dev/null
out=${RESULTS:-$(cd "$here/.." && pwd)/results}/$run_id
POLL=${POLL:-30} MARGIN=${MARGIN:-120} STEP=${STEP:-45}
SCREEN_WAIT=${SCREEN_WAIT:-10} GRACE=${GRACE:-20}
pkg=dev.tunbench
rundir=files/runs/$run_id
trace=/data/misc/perfetto-traces/tunbench-$run_id.pftrace

# Seconds an adb call may take; the wait for the run and the exit trap lower it.
limit=60
adb() { timeout -k 5 "$limit" "${adb_cmd[@]}" "$@"; }
dev() { adb shell "$@" | tr -d '\r'; }
as_app() { dev run-as "$pkg" "$@"; }
log() { printf '%s %s\n' "$(date +%T)" "$*" >&2; }
# A sleep a signal cuts short, so that the exit trap runs at once.
nap() {
  sleep "$1" &
  wait "$!"
}
die() {
  log "$*"
  exit 1
}

# Upper bound of the plan's running time in seconds: every measurement's window, its cooldown and
# STEP for the engine, warmup and teardown. Only a plan this cannot read fails here; the runner
# checks the rest when it starts.
deadline=$(
  python3 -I - "$plan" "$STEP" "$MARGIN" <<'PY'
import json
import sys

plan, step, margin = json.load(open(sys.argv[1])), int(sys.argv[2]), int(sys.argv[3])
total = 0
for case in plan["cases"]:
    if case["kind"] == "bulk":
        runs, seconds = len(case["flows"]), case["seconds"]
    elif case["kind"] == "tail":
        runs, seconds = 1, case["burst_seconds"] + case["observe_seconds"]
    else:
        runs, seconds = 1, case["seconds"]
    total += runs * (seconds + plan["cooldown_seconds"] + step)
print(len(plan["engines"]) * len(plan["mtu"]) * plan["repeat"] * total + margin)
PY
)

[ ! -e "$out" ] || die "$out exists; pick another RUN_ID"
dev true >/dev/null || die "no phone on adb"
mkdir -p "$out"

perfetto_pid=""
traced=0
started=0
finished=0

prop() { dev getprop "$1"; }
thermal() {
  local t
  t=$(dev dumpsys thermalservice | grep -m1 'Thermal Status' | cut -d: -f2 | tr -d ' ' || true)
  echo "${t:-unknown}"
}
# The lines the screen check reads. The display state comes from dumpsys display: on Android 17
# dumpsys power no longer prints it.
screen_state() {
  dev dumpsys power | grep 'mWakefulness=' || true
  dev dumpsys display | grep -m1 'Display State=' || true
  dev dumpsys activity activities | grep 'topResumedActivity=' || true
}
screen_ok() {
  local s
  s=$(screen_state)
  grep -q 'mWakefulness=Awake' <<<"$s" && grep -q 'Display State=ON' <<<"$s" &&
    grep -Eq 'topResumedActivity=.*dev\.tunbench/[A-Za-z.]*BenchActivity' <<<"$s"
}
await_screen() {
  local end=$((SECONDS + SCREEN_WAIT))
  until screen_ok; do
    [ "$SECONDS" -lt "$end" ] || return 1
    nap 1
  done
}

# Waits up to $1 seconds for the app's done file; fails early if the app died without it. No sleep
# or adb call runs past that time, and a done file seen after it does not count.
wait_done() {
  local end=$((SECONDS + $1)) left
  while left=$((end - SECONDS)) && [ "$left" -gt 0 ]; do
    if limit=$left as_app test -f "$rundir/done" 2>/dev/null; then
      [ "$SECONDS" -le "$end" ]
      return
    fi
    [ -n "$(limit=$left dev pidof "$pkg" || true)" ] || return 1
    left=$((end - SECONDS))
    [ "$left" -gt 0 ] || return 1
    log "waiting for the run: $SECONDS s of at most $deadline s"
    nap $((POLL < left ? POLL : left))
  done
  return 1
}

# Stops Perfetto and confirms on the phone that it has exited, so that the trace is complete.
stop_perfetto() {
  [ -n "$perfetto_pid" ] || return 0
  local p=$perfetto_pid
  local gone="for i in \$(seq 30); do kill -0 $p 2>/dev/null || { echo gone; exit; }; sleep 1; done"
  [ "$(limit=40 dev "kill -TERM $p; $gone")" = gone ] || {
    log "perfetto ($p) has not exited; its trace stays on the phone: $trace"
    return 1
  }
  perfetto_pid=""
}

# Saves what the app wrote, then the trace; the phone's copy of the trace goes only once it is here.
# Fails naming every file that is missing or empty here.
collect() {
  local f missing=()
  for f in plan.json results.jsonl 'done'; do
    adb exec-out run-as "$pkg" cat "$rundir/$f" >"$out/$f" 2>/dev/null || rm -f "$out/$f"
    [ -s "$out/$f" ] || missing+=("$f")
  done
  if limit=600 adb pull "$trace" "$out/trace.pftrace" >/dev/null 2>&1; then
    dev rm -f "$trace"
  else
    log "the trace was not pulled; it stays on the phone: $trace"
    missing+=(trace.pftrace)
  fi
  [ ${#missing[@]} = 0 ] || {
    log "missing or empty: ${missing[*]}"
    return 1
  }
}

cleanup() {
  local rc=$? fail=0 stay result
  trap - EXIT
  trap '' INT TERM
  set +e
  limit=30
  if [ "$started" = 1 ] && [ "$finished" = 0 ]; then
    dev am start -n "$pkg/.BenchActivity" --ez stop true --es run "$run_id" >/dev/null 2>&1
    wait_done "$GRACE"
  fi
  if [ "$traced" = 1 ]; then
    { stop_perfetto && collect; } || fail=1
  fi
  echo "thermal_status_end=$(thermal)" >>"$out/meta.txt"
  stay=$(dev settings get global stay_on_while_plugged_in 2>/dev/null)
  echo "stay_on_while_plugged_in_end=$stay" >>"$out/meta.txt"
  [ "$stay" = 0 ] || {
    log "stay_on_while_plugged_in is '$stay', not 0: the phone will not sleep on USB power"
    fail=1
  }
  if [ "$finished" = 1 ]; then
    result=$(cat "$out/done" 2>/dev/null)
    log "done: $result"
    [ "$result" = ok ] || fail=1
    echo "$out"
  fi
  [ "$rc" != 0 ] || rc=$fail
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

apk=$(dev pm path "$pkg" | head -1 | sed 's/^package://')
stay_start=$(dev settings get global stay_on_while_plugged_in)
{
  echo "run_id=$run_id"
  echo "plan_sha256=$(sha256sum "$plan" | cut -d' ' -f1)"
  echo "apk_sha256=$(dev sha256sum "$apk" | cut -d' ' -f1)"
  echo "build_id=$(prop ro.build.id)"
  echo "sdk_full=$(prop ro.build.version.sdk_full | grep . || prop ro.build.version.sdk)"
  echo "thermal_status_start=$(thermal)"
  echo "stay_on_while_plugged_in_start=$stay_start"
} >"$out/meta.txt"
# With it set, a run that fails before the black screen is up would leave the phone awake.
[ "$stay_start" = 0 ] || die "stay_on_while_plugged_in is '$stay_start', not 0; not waking the phone"

dev appops set "$pkg" ACTIVATE_VPN allow
dev input keyevent KEYCODE_WAKEUP
adb push "$plan" "/data/local/tmp/$run_id.json" >/dev/null
as_app mkdir -p files/plans
as_app cp "/data/local/tmp/$run_id.json" "files/plans/$run_id.json"
as_app rm -rf "$rundir"
dev rm -f "/data/local/tmp/$run_id.json"

dev rm -f "$trace"
traced=1
perfetto_pid=$(
  adb shell perfetto --background --txt -c - -o "$trace" <<EOF | tr -d '\r' | tail -1
buffers { size_kb: 32768 fill_policy: RING_BUFFER }
data_sources {
  config {
    name: "linux.ftrace"
    ftrace_config {
      ftrace_events: "sched/sched_switch"
      ftrace_events: "sched/sched_waking"
      compact_sched { enabled: true }
    }
  }
}
data_sources {
  config {
    name: "android.power"
    android_power_config { battery_poll_ms: 250 collect_power_rails: true }
  }
}
builtin_data_sources { primary_trace_clock: BUILTIN_CLOCK_BOOTTIME }
write_into_file: true
file_write_period_ms: 2500
max_file_size_bytes: 2147483648
duration_ms: $(((deadline + 60) * 1000))
EOF
)
case $perfetto_pid in
'' | *[!0-9]*)
  # Whatever it printed, a perfetto writing this trace must not outlive the run.
  perfetto_pid=$(dev pgrep -f "^perfetto .*$trace" | head -1 || true)
  die "perfetto did not start"
  ;;
esac

log "run $run_id: $plan, at most $deadline s"
started=1
answer=$(dev am start -n "$pkg/.BenchActivity" --es plan "$run_id.json" --es run "$run_id")
[[ $answer != *Error* ]] || {
  started=0
  die "the bench did not start: $answer"
}
await_screen || {
  screen_state >&2
  die "the phone is not awake with the bench in front"
}
{
  screen_state
  dev dumpsys display | grep -iE 'brightness|backlight' | head -50 || true
  echo "screen_brightness_setting=$(dev settings get system screen_brightness)"
} >"$out/screen.txt"

wait_done "$deadline" || die "no done file within $deadline s or the app died"
finished=1
