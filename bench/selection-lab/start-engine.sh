#!/bin/bash
# start-engine.sh honk|sing-box — start the selection-lab engine, wait ready.
set -u
case "$1" in
honk)
    RUST_LOG=honk_core=debug,honk_outbound=debug setsid /root/honk-new --config /root/honk-selection.dae >/root/honk-sel.log 2>&1 </dev/null &
    for _ in $(seq 1 20); do
        curl -s -m 2 http://127.0.0.1:9090/version >/dev/null 2>&1 && break
        sleep 1
    done
    curl -s -m 2 http://127.0.0.1:9090/version || { echo "HONK FAILED"; tail -20 /root/honk-sel.log; exit 1; }
    ;;
sing-box)
    ip netns exec lab setsid /root/sing-box run -c /root/sb-selection.json >/root/sb-sel.log 2>&1 </dev/null &
    for _ in $(seq 1 20); do
        ip netns exec lab curl -s -m 2 http://127.0.0.1:9091/version >/dev/null 2>&1 && break
        sleep 1
    done
    ip netns exec lab curl -s -m 2 http://127.0.0.1:9091/version || { echo "SB FAILED"; tail -20 /root/sb-sel.log; exit 1; }
    ;;
esac
echo
