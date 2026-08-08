#!/bin/bash
# QUIC-type direct UDP load A/B: juicity tunnel flow decided direct by domain
# rule, with and without HONK_UDP_POST_DECISION_OFFLOAD.
run_case() {
    local tag=$1 env=$2
    kill "$(pgrep -x juicity-client)" 2>/dev/null
    kill "$(pgrep -x honk)" 2>/dev/null; sleep 4
    ip link del dae0 2>/dev/null; ip netns del daens 2>/dev/null
    if [ "$env" = 1 ]; then
        HONK_UDP_POST_DECISION_OFFLOAD=1 setsid /root/honk --config /root/honk-udpoff-lab.dae >/root/honk-supp.log 2>&1 </dev/null &
    else
        setsid /root/honk --config /root/honk-udpoff-lab.dae >/root/honk-supp.log 2>&1 </dev/null &
    fi
    for _ in $(seq 1 20); do
        curl -s -m 2 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
        sleep 1
    done
    local pid
    pid=$(ss -tlnp | grep ':9090 ' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
    ip netns exec lab setsid /root/juicity-client run -c /root/juicity-2461-client.json >/root/juicity-supp.log 2>&1 </dev/null &
    sleep 3
    local t0 ms0 out ms1 t1
    t0=$(awk '{print $14+$15}' /proc/"$pid"/stat)
    ms0=$(date +%s%N)
    out=$(ip netns exec lab curl -s -o /dev/null -w "%{size_download} %{time_total}" \
        --socks5-hostname 127.0.0.1:11080 -m 20 http://10.10.10.70:8080/big.bin)
    ms1=$(date +%s%N)
    t1=$(awk '{print $14+$15}' /proc/"$pid"/stat)
    python3 - "$tag" "$pid" $t0 $t1 $ms0 $ms1 $out <<'PY'
import sys
tag, pid, t0, t1, ms0, ms1, size, secs = sys.argv[1:9]
cores = (int(t1)-int(t0))/100/((int(ms1)-int(ms0))/1e9)
mbps = int(size)*8/float(secs)/1e6
print(f"{tag}: bytes={size} t={secs}s -> {mbps:.1f} Mbps, honk cpu={cores:.2f} cores (pid {pid})")
PY
    curl -s -m 3 http://127.0.0.1:9090/stats | python3 -c "
import json,sys
d=json.load(sys.stdin).get('udp',{})
print('  $tag endpoint:', d.get('endpoint'), 'dialcnt:', d.get('latency',{}).get('dial',{}).get('count'))"
    grep -E "Connecting|Authenticated" /root/juicity-supp.log | tail -2
}
run_case offload-on 1
run_case offload-off 0
kill "$(pgrep -x juicity-client)" 2>/dev/null
kill "$(pgrep -x honk)" 2>/dev/null; sleep 3
ip link del dae0 2>/dev/null; ip netns del daens 2>/dev/null
echo supp-done
