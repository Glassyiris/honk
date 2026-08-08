#!/bin/bash
# lab-bench-ab.sh — lab-bench-arm.sh extended with the dae engine for the
# honk-vs-dae A/B round on 10.10.10.43. Methodology identical to
# bench/lab-bench.sh.
set -u

T=10.10.10.70
N=lab
HOT_N=15
BW_RUNS=3
BW_TIME=8
COLD_RUNS=3
TSV=/root/bench-ab-results.tsv

ENGINES=${1:-"honk"}
PROTOS=${2:-"hy2 tuic ss2022 trojan"}

# protocol → index (ports: 800<idx> http, 520<idx> iperf3)
proto_idx() {
    case $1 in
    hy2) echo 1 ;;
    tuic) echo 2 ;;
    ss2022) echo 3 ;;
    trojan) echo 4 ;;
    anytls-sb) echo 5 ;;
    anytls-go) echo 6 ;;
    vless-vision) echo 7 ;;
    vless-reality) echo 8 ;;
    vmess) echo 9 ;;
    *) echo 0 ;;
    esac
}

cpu_ticks() {
    [ -n "$1" ] || {
        echo 0
        return
    }
    awk '{print $14+$15}' /proc/"$1"/stat 2>/dev/null || echo 0
}
rss_mb() {
    [ -n "$1" ] || {
        echo 0
        return
    }
    awk '/VmRSS/{print int($2/1024)}' /proc/"$1"/status 2>/dev/null || echo 0
}

stop_engines() {
    pkill -f "/root/hon[k]" 2>/dev/null
    pkill -f "/root/da[e] run" 2>/dev/null
    local sb_running
    sb_running=$(pgrep -f "sing-bo[x] run" 2>/dev/null)
    pkill -f "sing-bo[x] run" 2>/dev/null
    for _ in $(seq 1 30); do
        pgrep -f "/root/hon[k]" >/dev/null && {
            sleep 1
            continue
        }
        pgrep -f "/root/da[e] run" >/dev/null && {
            sleep 1
            continue
        }
        pgrep -f "sing-bo[x] run" >/dev/null && {
            sleep 1
            continue
        }
        break
    done
    # both engines own the fixed dae0/daens datapath names; a crashed engine
    # can leave them behind and wedge the next engine's attach
    if ! pgrep -f "/root/hon[k]" >/dev/null && ! pgrep -f "/root/da[e] run" >/dev/null; then
        ip link del dae0 2>/dev/null
        ip netns del daens 2>/dev/null
    fi
    [ -n "$sb_running" ] && bash /root/setup-netns.sh >/dev/null 2>&1
}

start_engine() { # engine → prints pid
    stop_engines
    case $1 in
    honk)
        setsid /root/honk --config /root/honk-lab.dae >/root/honk.log 2>&1 </dev/null &
        for _ in $(seq 1 20); do
            curl -s -m 2 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
            sleep 1
        done
        ss -tlnp | grep ':9090 ' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1
        ;;
    dae)
        setsid /root/dae run -c /root/dae-lab.dae >/root/dae.log 2>&1 </dev/null &
        for _ in $(seq 1 30); do
            ip link show dae0 >/dev/null 2>&1 && ip netns list | grep -q '^daens' && break
            pgrep -f "/root/da[e] run" >/dev/null || break
            sleep 1
        done
        sleep 2
        pgrep -f "/root/da[e] run" | head -1
        ;;
    esac
}

ncurl() { # port → time_total (seconds, empty on failure)
    ip netns exec $N curl -s -o /dev/null -w "%{time_total}" -m 20 "http://$T:$1/" 2>/dev/null
}

median() {
    sort -n | awk '{a[NR]=$1} END{print (NR%2)? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2}'
}

pct() {
    sort -n | awk -v p="$1" '{a[NR]=$1} END{i=int((p/100)*NR+0.999); if(i<1)i=1; if(i>NR)i=NR; print a[i]}'
}

cold_latency() { # engine port → median of COLD_RUNS fresh-engine first requests
    local runs=""
    for _ in $(seq 1 $COLD_RUNS); do
        start_engine "$1" >/dev/null
        sleep 2
        runs="$runs $(ncurl "$2")"
    done
    echo $runs | tr ' ' '\n' | grep -E '^[0-9.]+$' | median
}

hot_latency() { # port → "p50 p95" over HOT_N requests (first is warmup)
    ncurl "$1" >/dev/null
    local vals=""
    for _ in $(seq 1 $HOT_N); do
        vals="$vals $(ncurl "$1")"
    done
    local p50 p95
    p50=$(echo $vals | tr ' ' '\n' | grep -E '^[0-9.]+$' | pct 50)
    p95=$(echo $vals | tr ' ' '\n' | grep -E '^[0-9.]+$' | pct 95)
    echo "$p50 $p95"
}

bandwidth() { # pid iperf_port → "median_mbps cpu_cores"
    local pid=$1 port=$2
    local results="" i bw ticks0 ticks1 ms0 ms1 cores
    for i in $(seq 1 $BW_RUNS); do
        ticks0=$(cpu_ticks "$pid")
        ms0=$(date +%s%N)
        bw=$(ip netns exec $N iperf3 -c $T -p "$port" -t $BW_TIME -R -J 2>/dev/null |
            python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); print(int(d["end"]["sum_received"]["bits_per_second"]/1e6))
except Exception: print(0)')
        ms1=$(date +%s%N)
        ticks1=$(cpu_ticks "$pid")
        cores=$(python3 -c "print(f'{($ticks1-$ticks0)/100/(($ms1-$ms0)/1e9):.2f}')")
        results="$results$bw:$cores\n"
    done
    echo -e "$results" | grep -E '^[0-9]+:' | sort -t: -k1 -n |
        awk -F: '{a[NR]=$1; c[NR]=$2} END{m=int((NR+1)/2); printf "%s %s", a[m], c[m]}'
}

row() {
    printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "$@"
}

udp_echo_rtt() { # idx → p50 seconds
    ip netns exec $N python3 - "$1" <<'PY' 2>/dev/null
import socket, sys, time
port = 53530 + int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
rtts = []
for _ in range(15):
    t = time.time()
    try:
        s.sendto(b"lab-udp-ping", ("10.10.10.70", port))
        s.recvfrom(64)
        rtts.append(time.time() - t)
    except Exception:
        pass
rtts.sort()
print(f"{rtts[len(rtts)//2]:.6f}" if rtts else "")
PY
}

udp_bandwidth() { # pid iperf_port → "mbps(loss%) cores"
    local pid=$1 port=$2
    local ticks0 ticks1 ms0 ms1 res
    ticks0=$(cpu_ticks "$pid")
    ms0=$(date +%s%N)
    res=$(ip netns exec $N iperf3 -c $T -p "$port" -u -b 10G -l 1200 -t $BW_TIME -R -J 2>/dev/null |
        python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); e=d["end"]
    mbps = int(e["sum_received"]["bits_per_second"]/1e6)
    loss = e["sum"]["lost_percent"]
    print("%d(%.1f%%)" % (mbps, loss))
except Exception: print("0(-)")')
    ms1=$(date +%s%N)
    ticks1=$(cpu_ticks "$pid")
    echo "$res $(python3 -c "print(f'{($ticks1-$ticks0)/100/(($ms1-$ms0)/1e9):.2f}')")"
}

echo "# lab-bench $(date -u +%Y-%m-%dT%H:%M:%SZ) engines=($ENGINES) protos=($PROTOS)" >&2
row engine protocol 'cold(s)' 'hot p50(s)' 'hot p95(s)' 'bw(Mbps)' 'cpu(cores)' 'rss(MB)'
row '---' '---' '---' '---' '---' '---' '---' '---'

for engine in $ENGINES; do
    echo "# engine=$engine" >&2
    pid=$(start_engine "$engine")
    direct_cold=$(ncurl 8080)
    read -r direct_bw direct_cpu <<<"$(bandwidth "$pid" 5300)"
    row "$engine" direct "$direct_cold" '-' '-' "$direct_bw" "$direct_cpu" "$(rss_mb "$pid")"
    echo "$engine|direct|$direct_cold|-|-|$direct_bw|$direct_cpu|$(rss_mb "$pid")" >>$TSV

    for proto in $PROTOS; do
        idx=$(proto_idx "$proto")
        [ "$idx" = 0 ] && continue
        cold=$(cold_latency "$engine" 800"$idx")
        pid=$(start_engine "$engine")
        read -r p50 p95 <<<"$(hot_latency 800"$idx")"
        read -r bw cores <<<"$(bandwidth "$pid" 520"$idx")"
        rss=$(rss_mb "$pid")
        row "$engine" "$proto" "$cold" "$p50" "$p95" "$bw" "$cores" "$rss"
        echo "$engine|$proto|$cold|$p50|$p95|$bw|$cores|$rss" >>$TSV
        urtt=$(udp_echo_rtt "$idx")
        read -r ubw ucores <<<"$(udp_bandwidth "$pid" 520"$idx")"
        row "$engine" "$proto/udp" "$urtt" '-' '-' "$ubw" "$ucores" '-'
        echo "$engine|$proto/udp|$urtt|-|-|$ubw|$ucores|-" >>$TSV
    done
done
stop_engines
