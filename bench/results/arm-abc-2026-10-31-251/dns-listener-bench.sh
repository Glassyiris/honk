#!/bin/bash
# DNS listener comparison: honk vs dae vs sing-box, one engine at a time.
# Client runs in netns "lab"; honk/dae expose dns.bind on 192.168.222.1:15353,
# sing-box answers through its TUN with a port-53 hijack rule (client hits 1.1.1.1:53).
set -u
D=/tmp/eries-bench-arm-20261030
LOAD=$D/bin/dnsload
HONK=$D/bin/honk-core
DAE=$D/bin/dae
SB=$D/bin/sing-box
OUT=$D/dns-listener
SECONDS_PER_CASE=${SECONDS_PER_CASE:-15}
PORT=15353
mkdir -p "$OUT"
ENGINE_PID=

log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }

start_honk() {
    "$HONK" -c "$D/honk-dns.dae" > "$OUT/honk.log" 2>&1 &
    ENGINE_PID=$!
}
start_dae() {
    "$DAE" run -c "$D/dae-dns.dae" --disable-pidfile > "$OUT/dae.log" 2>&1 &
    ENGINE_PID=$!
}
start_sb() {
    ip netns exec lab "$SB" run -c "$D/sb-dns.json" > "$OUT/sing-box.log" 2>&1 &
    ENGINE_PID=$!
}
stop_engine() {
    [ -n "${ENGINE_PID:-}" ] || return 0
    kill "$ENGINE_PID" 2>/dev/null
    for _ in $(seq 1 40); do kill -0 "$ENGINE_PID" 2>/dev/null || break; sleep 0.25; done
    kill -9 "$ENGINE_PID" 2>/dev/null
    wait "$ENGINE_PID" 2>/dev/null
    ENGINE_PID=
    ip netns exec lab ip link del sbdns0 2>/dev/null
    ip link del dae0 2>/dev/null
    sleep 1
}

wait_ready() {
    local engine=$1
    for _ in $(seq 1 80); do
        case $engine in
            honk|dae) python3 -c "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((\"192.168.222.1\",15353)); sys.exit(1)" 2>&1 && return 0 ;;
            sing-box) ip netns exec lab ip link show sbdns0 >/dev/null 2>&1 && return 0 ;;
        esac
        sleep 0.25
    done
    return 1
}

verify_answer() {
    local engine=$1 host=$2 port=$3 answer
    answer=$(ip netns exec lab python3 "$D/dns-answer.py" "$host" "$port")
    echo "$engine answered A=$answer (fixture expects 192.0.2.42)" >> "$OUT/answer-check.txt"
    [ "$answer" = "192.0.2.42" ] || { log "$engine answer mismatch: $answer"; return 1; }
}

cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
rss_kb() { awk '/VmRSS/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }

run_case() {
    local engine=$1 target_host=$2 mode=$3 threads=$4 pid ticks0 ticks1 rss cores line
    pid=$ENGINE_PID
    [ "$engine" = sing-box ] && pid=$(pgrep -f "sing-box run -c $D/sb-dns.json" | head -1)
    ticks0=$(cpu_ticks "$pid"); rss=$(rss_kb "$pid")
    line=$(ip netns exec lab "$LOAD" "$target_host" \
        "$([ "$engine" = sing-box ] && echo 53 || echo $PORT)" "$threads" "$SECONDS_PER_CASE" "$mode")
    ticks1=$(cpu_ticks "$pid"); rss=$(rss_kb "$pid")
    cores=$(awk -v a="$ticks0" -v b="$ticks1" -v hz=100 -v s="$SECONDS_PER_CASE" \
        'BEGIN{printf "%.2f", (b-a)/hz/s}')
    echo "$engine|$line|$cores|$rss" | tee -a "$OUT/results.tsv"
}

run_engine() {
    local engine=$1 host=$2
    log "start $engine"
    case $engine in
        honk) start_honk ;;
        dae) start_dae ;;
        sing-box) start_sb ;;
    esac
    if ! wait_ready "$engine"; then
        log "$engine did not become ready"
        tail -5 "$OUT/$engine.log" >&2
        stop_engine
        return 1
    fi
    sleep 2
    verify_answer "$engine" "$host" "$([ "$engine" = sing-box ] && echo 53 || echo $PORT)" || {
        stop_engine
        return 1
    }
    run_case "$engine" "$host" cache 1
    run_case "$engine" "$host" cache 8
    run_case "$engine" "$host" unique 1
    run_case "$engine" "$host" unique 8
    stop_engine
    log "stop $engine"
}

: > "$OUT/results.tsv"
: > "$OUT/answer-check.txt"
printf 'engine|mode|threads|qps|ok|fail|p50_us|p95_us|p99_us|max_us|cpu_cores|rss_kb\n' >> "$OUT/results.tsv"

run_engine honk 192.168.222.1
run_engine dae 192.168.222.1
run_engine sing-box 1.1.1.1

for mode in cache unique; do
    for threads in 1 8; do
        line=$(ip netns exec lab "$LOAD" 10.10.10.70 53539 "$threads" "$SECONDS_PER_CASE" "$mode")
        echo "direct|$line|0.00|0" | tee -a "$OUT/results.tsv"
    done
done
log DONE
