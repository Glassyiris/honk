#!/bin/bash
# probes.sh [api_port] [netns?] — print group pick + per-node last delays.
port=${1:-9090}
prefix=""
[ "${2:-}" = netns ] && prefix="ip netns exec lab"
for _ in $(seq 1 30); do
    n=$($prefix curl -s -m 2 "http://127.0.0.1:$port/proxies" | python3 -c '
import json,sys
d=json.load(sys.stdin)["proxies"]
print(sum(1 for r in ("relay-a","relay-b","relay-c") if d.get(r,{}).get("history")))
' 2>/dev/null)
    [ "$n" = 3 ] && break
    sleep 3
done
$prefix curl -s -m 2 "http://127.0.0.1:$port/proxies" | python3 -c '
import json,sys
d=json.load(sys.stdin)["proxies"]
print("NOW:", d["proxy"].get("now"))
for r in ("relay-a","relay-b","relay-c"):
    h=d[r]["history"]
    print(r, "last:", h[-1]["delay"] if h else "-", "samples:", len(h))
'
