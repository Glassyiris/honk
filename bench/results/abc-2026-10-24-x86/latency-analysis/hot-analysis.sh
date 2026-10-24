#!/bin/bash
# hot-analysis.sh ENGINE — per-request timings and upstream connection counts
# for the standard six-protocol fixture. Runs on 10.10.10.70.
set -u
E=$1
D=/tmp/hot-$E
mkdir -p "$D"
R="ssh -o BatchMode=yes root@10.10.10.49"

case $E in
honk)
    $R 'pkill -x honk-core 2>/dev/null; pkill -x dae 2>/dev/null; pkill -x sing-box 2>/dev/null; sleep 1
        ip link del dae0 2>/dev/null; ip netns del daens 2>/dev/null; rm -f /run/netns/daens
        bash /root/setup-netns.sh
        setsid /root/honk-bench-abc-20261024/bin/honk-core -c /root/honk-bench-abc-20261024/honk-lab.dae >/root/hot-honk.log 2>&1 </dev/null &
        for i in $(seq 1 25); do curl -s -m1 http://127.0.0.1:9090/version >/dev/null && break; sleep 1; done; sleep 1'
    ;;
dae)
    $R 'pkill -x honk-core 2>/dev/null; pkill -x dae 2>/dev/null; pkill -x sing-box 2>/dev/null; sleep 1
        ip link del dae0 2>/dev/null; ip netns del daens 2>/dev/null; rm -f /run/netns/daens
        bash /root/setup-netns.sh
        setsid /root/honk-bench-abc-20261024/bin/dae run -c /root/honk-bench-abc-20261024/dae-lab.dae >/root/hot-dae.log 2>&1 </dev/null &
        for i in $(seq 1 30); do ip link show dae0 >/dev/null 2>&1 && ip netns list | grep -q daens && break; sleep 1; done; sleep 2'
    ;;
sing-box)
    $R 'pkill -x honk-core 2>/dev/null; pkill -x dae 2>/dev/null; pkill -x sing-box 2>/dev/null; sleep 1
        ip link del dae0 2>/dev/null; ip netns del daens 2>/dev/null; rm -f /run/netns/daens
        bash /root/setup-netns.sh
        ip netns exec lab setsid /root/honk-bench-abc-20261024/bin/sing-box run -c /root/honk-bench-abc-20261024/sb-client.json >/root/hot-sb.log 2>&1 </dev/null &
        sleep 5'
    ;;
*) echo "usage: $0 honk|dae|sing-box" >&2; exit 2 ;;
esac

declare -A client=( [hy2]=8001 [tuic]=8002 [ss2022]=8003 [trojan]=8004 [anytls-sb]=8005 [anytls-go]=8006 )
declare -A server=( [hy2]=8443 [tuic]=2444 [ss2022]=2447 [trojan]=2446 [anytls-sb]=2445 [anytls-go]=2443 )

for proto in tuic ss2022 trojan anytls-sb anytls-go hy2; do
    port=${client[$proto]}
    sp=${server[$proto]}
    cap=$D/$proto.cap
    : >"$cap"
    if [ "$proto" = hy2 ] || [ "$proto" = tuic ]; then
        tcpdump -l -i any -n "src host 10.10.10.49 and udp dst port $sp" >"$cap" 2>/dev/null &
    else
        tcpdump -l -i any -n "src host 10.10.10.49 and dst port $sp and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" >"$cap" 2>/dev/null &
    fi
    cap_pid=$!
    sleep 0.5
    $R "bash /root/hot-probe.sh $port 5 30" >"$D/$proto.times"
    kill "$cap_pid" 2>/dev/null
    wait "$cap_pid" 2>/dev/null
    if [ "$proto" = hy2 ] || [ "$proto" = tuic ]; then
        ports=$(awk '/IP /{split($3,a,"."); print a[5]}' "$cap" | sort -u | wc -l)
        echo "$proto udp_source_ports=$ports" >>"$D/summary"
    else
        syns=$(grep -c 'Flags \[S\]' "$cap")
        echo "$proto upstream_syns=$syns" >>"$D/summary"
    fi
done

$R 'pkill -x honk-core 2>/dev/null; pkill -x dae 2>/dev/null; pkill -x sing-box 2>/dev/null; true'
cat "$D/summary"
