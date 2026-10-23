#!/bin/bash
# serve.sh standard|rprx|status — `.70` lab server fixture for the 2026-10-24
# A/B/C campaign. Targets, iperf3, anytls-go and juicity run across mode
# switches; only the sing-box server (8443 conflicts between hy2 and
# vless-vision) is replaced.
set -u
D=/root/bench-20261024
mkdir -p "$D/logs"

start_targets() {
    pgrep -f "$D/target-fixture.py" >/dev/null ||
        setsid nohup python3 "$D/target-fixture.py" >>"$D/logs/target.log" 2>&1 </dev/null &
    local port
    for port in 5201 5202 5203 5204 5205 5206 5300; do
        pgrep -f "iperf3 -s -p $port" >/dev/null ||
            iperf3 -s -p "$port" -D --logfile "$D/logs/iperf-$port.log"
    done
    pgrep -f "anytls-server -l 0.0.0.0:2443" >/dev/null ||
        setsid nohup "$D/bin/anytls-server" -l 0.0.0.0:2443 -p testpass123 \
            >>"$D/logs/anytls.log" 2>&1 </dev/null &
    pgrep -f "juicity-server run" >/dev/null ||
        setsid nohup "$D/bin/juicity-server" run -c "$D/juicity-server.json" \
            >>"$D/logs/juicity.log" 2>&1 </dev/null &
    sleep 1
}

case "${1:-standard}" in
standard) conf=$D/singbox-server.json ;;
rprx) conf=$D/singbox-rprx.json ;;
status)
    ss -ltnup | grep -E ':(2443|2444|2445|2446|2447|8443|8444|8445|8446|2451|800[0-9]|8080|520[0-9]|5300)\b'
    pgrep -af 'bench-20261024|iperf3 -s'
    exit 0
    ;;
*)
    echo "usage: serve.sh standard|rprx|status" >&2
    exit 2
    ;;
esac

pkill -f "$D/bin/sing-box run" 2>/dev/null
for _ in $(seq 1 20); do
    pgrep -f "$D/bin/sing-box run" >/dev/null || break
    sleep 0.5
done
setsid nohup "$D/bin/sing-box" run -c "$conf" >>"$D/logs/sing-box.log" 2>&1 </dev/null &
start_targets
sleep 2
pgrep -af "$D/bin/sing-box run"
