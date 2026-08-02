#!/bin/bash
# flip-watch.sh <api_port> [netns] <rounds> — after a quality flip, watch the
# group pick and per-request latency over time.
set -u
api=$1
prefix=""
[ "${2:-}" = netns ] && prefix="ip netns exec lab"
rounds=$3
for i in $(seq 1 "$rounds"); do
    now=$($prefix curl -s -m 2 "http://127.0.0.1:$api/proxies" | python3 -c '
import json,sys
d=json.load(sys.stdin)["proxies"]
g=d["proxy"]
h=g.get("history",[])
print(g.get("now"), h[-1]["delay"] if h else "-")
' 2>/dev/null)
    t=$(ip netns exec lab curl -s -o /dev/null -w "%{time_total}" -m 20 "http://10.10.10.70:9001/" 2>/dev/null)
    echo "t+$((i*2))s pick=$now site=${t:-FAIL}"
    sleep 2
done
