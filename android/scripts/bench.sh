#!/bin/bash
# TunBench driver: Android VpnService tun throughput plus CPU cost per byte, per engine.
# Runs on a host with adb (USB) to the phone and ssh to Termux on the same phone.
#
# Usage: bench.sh [-e "engines"] [-m "mtu ..."] [-n reps] [-t seconds] [-c cooldown] [-T "tests"]
#                 [-C cpus] [-A cpus]
#   engines  TunBench engines to interleave (default "hev honk")
#   tests    iperf3 option sets, separated by commas, e.g. "single,-R,-P 4,-P 4 -R"
#   -C cpus  pin the Termux side (iperf3 client and server, socks-redir) to this CPU list, e.g. 0-6
#   -A cpus  pass --es cpus to TunBench: pin the engine's worker thread (must lie in the app's cpuset)
#
# Environment:
#   TERMUX_SSH   required: ssh arguments that reach Termux, e.g. "-p 8022 u0_a123@phone.lan"
#   OUT          output directory (default ./runs); one TSV row per run in <timestamp>-<engines>.tsv
#   SOCKS_PORT   port of the SOCKS5 redirector in Termux, used by hev (default 1081)
#   SOCKS_REDIR  command in Termux that serves SOCKS5 on SOCKS_PORT and connects every request to
#                127.0.0.1:IPERF_PORT; started as "$SOCKS_REDIR SOCKS_PORT 127.0.0.1 IPERF_PORT"
#                (default ~/socks-redir)
#   IPERF_PORT   iperf3 server port in Termux; the honk engine connects to it directly (default 5202)
#   TARGET       iperf3 client target, an address TunBench routes into the tun (default 198.18.0.1)
#   FREQ_CPUS    CPUs whose scaling_cur_freq is sampled mid-run, one per cluster (default "7 2 0")
set -u
ENGINES="hev honk"; MTUS="8500"; REPS=5; DUR=10; COOL=30
TESTS="single,-R,-P 4,-P 4 -R,-P 8,-P 8 -R"; TCPUS=""; ACPUS=""
while getopts "e:m:n:t:c:T:C:A:" o; do case $o in
  e) ENGINES=$OPTARG;; m) MTUS=$OPTARG;; n) REPS=$OPTARG;; t) DUR=$OPTARG;;
  c) COOL=$OPTARG;; T) TESTS=$OPTARG;; C) TCPUS=$OPTARG;; A) ACPUS=$OPTARG;; *) exit 2;; esac; done

: "${TERMUX_SSH:?set TERMUX_SSH to the ssh arguments that reach Termux}"
SOCKS_PORT=${SOCKS_PORT:-1081}; IPERF_PORT=${IPERF_PORT:-5202}; TARGET=${TARGET:-198.18.0.1}
SOCKS_REDIR=${SOCKS_REDIR:-'~/socks-redir'}; FREQ_CPUS=${FREQ_CPUS:-"7 2 0"}
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8 $TERMUX_SSH"
OUT=${OUT:-$PWD/runs}; mkdir -p "$OUT"
LOG=$OUT/$(date +%Y%m%d-%H%M%S)-${ENGINES// /+}${TCPUS:+-termux$TCPUS}${ACPUS:+-app$ACPUS}.tsv
HZ=100   # Android CLK_TCK

# app CPU ticks (utime+stime) of the VPN process; Termux side: socks-redir + iperf3 server
app_ticks() { local p; p=$(adb shell pidof dev.tunbench | tr -d '\r'); [ -n "$p" ] &&
  adb shell "cut -d' ' -f14,15 /proc/$p/stat" | tr -d '\r' || echo "0 0"; }
termux_ticks() { $SSH 'for p in $(pgrep -x socks-redir) $(pgrep -f "iperf3 -s"); do cut -d" " -f14,15 /proc/$p/stat; done' |
  awk '{u+=$1; s+=$2} END {print u+0, s+0}'; }
# live readings only: the "Current temperatures from HAL" block (the "Cached" block is stale).
# The sensor names are those of Pixel devices; other phones report other names or none.
thermal() { adb shell dumpsys thermalservice | tr -d '\r' |
  awk -F'[=,]' '/^Current temperatures from HAL/ {f=1; next} f && /^[A-Z]/ {f=0}
    f && /mName=(BIG|MID|LITTLE|VIRTUAL-SKIN),/ {printf "%s=%.1f ", $6, $2}' | sed 's/ $//'; }
freqs() { local c paths=""
  for c in $FREQ_CPUS; do paths="$paths /sys/devices/system/cpu/cpu$c/cpufreq/scaling_cur_freq"; done
  adb shell "cat $paths" | tr -d '\r' | awk '{printf "%s%d", (NR>1 ? "/" : ""), $1/1000}'; }

start_vpn() { # $1 engine, $2 mtu
  local port=$SOCKS_PORT; [ "$1" = honk ] && port=$IPERF_PORT
  adb shell am start -n dev.tunbench/.MainActivity --es action stop >/dev/null 2>&1; sleep 2
  adb shell am start -n dev.tunbench/.MainActivity --es action start --es engine "$1" \
    --es host 127.0.0.1 --es port "$port" --es mtu "$2" ${ACPUS:+--es cpus "$ACPUS"} >/dev/null 2>&1
  sleep 3
}

adb shell svc power stayon usb
trap 'adb shell svc power stayon false' EXIT
$SSH "pgrep -x socks-redir >/dev/null || tmux new-session -d -s socks \"$SOCKS_REDIR $SOCKS_PORT 127.0.0.1 $IPERF_PORT\";
      pgrep -f 'iperf3 -s' >/dev/null || iperf3 -s -D -B 127.0.0.1 -p $IPERF_PORT"
CLIENT="iperf3"
if [ -n "$TCPUS" ]; then
  $SSH "for p in \$(pgrep -x socks-redir) \$(pgrep -f 'iperf3 -s'); do taskset -a -p -c $TCPUS \$p >/dev/null; done"
  CLIENT="taskset -c $TCPUS iperf3"
fi

printf "engine\tmtu\ttest\trep\tgbps\tgbytes\tapp_user_s\tapp_sys_s\tapp_cores\tapp_cpu_s_per_gb\ttermux_cpu_s\tawake\tfreq_mhz_mid\ttemps_mid\ttermux_cpus\tapp_cpus\tapp_cpuset\n" > "$LOG"
IFS=',' read -ra TL <<< "$TESTS"
for mtu in $MTUS; do
  for rep in $(seq 1 "$REPS"); do
    for t in "${TL[@]}"; do
      for eng in $ENGINES; do   # engines interleave inside each rep so heat and load hit all of them
        start_vpn "$eng" "$mtu"
        opt=$t; [ "$t" = single ] && opt=""
        read -r au0 as0 <<< "$(app_ticks)"; read -r tu0 ts0 <<< "$(termux_ticks)"
        mid=$(mktemp); ( sleep $((DUR / 2)); printf "%s\t%s" "$(freqs)" "$(thermal)" > "$mid" ) &
        res=$($SSH "timeout $((DUR + 15)) $CLIENT -c $TARGET -p $IPERF_PORT -t $DUR -f g $opt 2>&1 | grep -E 'receiver' | tail -1")
        wait; sample=$(cat "$mid"); rm -f "$mid"
        cs=$(adb shell "cat /proc/\$(pidof dev.tunbench)/cpuset" | tr -d '\r')
        read -r au1 as1 <<< "$(app_ticks)"; read -r tu1 ts1 <<< "$(termux_ticks)"
        gbps=$(grep -oE '[0-9.]+ Gbits/sec' <<< "$res" | grep -oE '^[0-9.]+'); gbps=${gbps:-fail}
        gb=$(grep -oE '[0-9.]+ GBytes' <<< "$res" | grep -oE '^[0-9.]+'); gb=${gb:-0}
        line=$(awk -v hz=$HZ -v d="$DUR" -v gb="$gb" -v au=$((au1-au0)) -v as=$((as1-as0)) -v tc=$((tu1-tu0+ts1-ts0)) 'BEGIN{
          u=au/hz; s=as/hz; c=(u+s)/d; per=(gb>0)?(u+s)/gb:0
          printf "%.2f\t%.2f\t%.2f\t%.3f\t%.2f", u, s, c, per, tc/hz }')
        awake=$(adb shell dumpsys power | grep -oE 'mWakefulness=[A-Za-z]+' | head -1 | cut -d= -f2 | tr -d '\r')
        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$eng" "$mtu" "$t" "$rep" "$gbps" "$gb" "$line" "$awake" "$sample" "${TCPUS:-any}" "${ACPUS:-any}" "$cs" | tee -a "$LOG"
        sleep "$COOL"
      done
    done
  done
done
echo "LOG=$LOG"
