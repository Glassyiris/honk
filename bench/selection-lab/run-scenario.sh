#!/bin/bash
# run-scenario.sh <honk|sing-box> <label> <rounds> — full scenario cycle:
# fresh engine, warm the group, measure per-site latency through the pick.
set -u
engine=$1
label=$2
rounds=$3
bash /root/stop-engines.sh
bash /root/start-engine.sh "$engine" >/dev/null || { echo "$label: engine start failed"; exit 1; }
# Wake health checks / urltest and let measurements converge.
case "$engine" in
honk)
    for port in 9001 9002 9003; do
        ip netns exec lab curl -s -o /dev/null -m 10 "http://10.10.10.70:$port/" 2>/dev/null || true
    done
    sleep 12
    api=9090; prefix=""
    ;;
sing-box)
    sleep 12
    api=9091; prefix="ip netns exec lab"
    ;;
esac
echo "== $label engine=$engine =="
$prefix curl -s -m 2 "http://127.0.0.1:$api/proxies" | python3 -c '
import json,sys
d=json.load(sys.stdin)["proxies"]
print("NOW:", d["proxy"].get("now"))
for r in ("relay-a","relay-b","relay-c"):
    h=d[r]["history"]
    print(r, "last:", h[-1]["delay"] if h else "-", "samples:", len(h))
'
for port in 9001 9002 9003; do
    vals=""
    for _ in $(seq 1 "$rounds"); do
        t=$(ip netns exec lab curl -s -o /dev/null -w "%{time_total}" -m 20 "http://10.10.10.70:$port/" 2>/dev/null)
        vals="$vals ${t:-FAIL}"
    done
    echo "site $port:$vals"
done
