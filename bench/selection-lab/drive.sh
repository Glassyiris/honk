#!/bin/bash
# drive.sh <engine> <rounds> — curl each site <rounds> times from the lab
# netns, print "site time_total" per request, then the group's selection.
set -u
engine=$1
rounds=$2
for port in 9001 9002 9003; do
    for _ in $(seq 1 "$rounds"); do
        t=$(ip netns exec lab curl -s -o /dev/null -w "%{time_total}" -m 20 "http://10.10.10.70:$port/" 2>/dev/null)
        echo "$port ${t:-FAIL}"
    done
done
case "$engine" in
honk)
    curl -s -m 3 http://127.0.0.1:9090/proxies | python3 -c '
import json,sys
d=json.load(sys.stdin)["proxies"]
g=d.get("proxy",{})
print("NOW", g.get("now"))
for n in ("relay-a","relay-b","relay-c"):
    h=d.get(n,{}).get("history",[])
    print(n, h[-1].get("delay") if h else "-")
' ;;
sing-box)
    ip netns exec lab curl -s -m 3 http://127.0.0.1:9091/proxies | python3 -c '
import json,sys
d=json.load(sys.stdin)["proxies"]
g=d.get("proxy",{})
print("NOW", g.get("now"))
for n in ("relay-a","relay-b","relay-c"):
    h=d.get(n,{}).get("history",[])
    print(n, h[-1].get("delay") if h else "-")
' ;;
esac
