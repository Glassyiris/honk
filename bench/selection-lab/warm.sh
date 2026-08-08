#!/bin/bash
# warm.sh <honk|sing-box> — fresh engine + wake health checks + converge.
set -u
bash /root/stop-engines.sh
bash /root/start-engine.sh "$1" >/dev/null || exit 1
if [ "$1" = honk ]; then
    for port in 9001 9002 9003; do
        ip netns exec lab curl -s -o /dev/null -m 10 "http://10.10.10.70:$port/" 2>/dev/null || true
    done
fi
sleep 12
