#!/usr/bin/env python3
# AF_PACKET UDP sniffer: logs ts, tuple, len for packets matching a host.
# usage: udp-sniff.py <iface> <host-ip> <outfile>
import socket, struct, sys, time, datetime

iface, host, out = sys.argv[1], sys.argv[2], sys.argv[3]
host_b = socket.inet_aton(host)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
s.bind((iface, 0))
f = open(out, "a", buffering=1)
f.write("# start %s iface=%s host=%s\n" % (datetime.datetime.now().isoformat(), iface, host))
while True:
    pkt = s.recvfrom(65535)[0]
    if len(pkt) < 42 or pkt[12:14] != b"\x08\x00":
        continue
    ihl = (pkt[14] & 0x0F) * 4
    if pkt[23] != 17:  # udp only
        continue
    src, dst = pkt[26:30], pkt[30:34]
    if src != host_b and dst != host_b:
        continue
    ts = time.time()
    ip_off = 14
    sport, dport, ulen = struct.unpack("!HHH", pkt[ip_off + ihl:ip_off + ihl + 6])
    f.write("%.6f %s:%d > %s:%d len=%d\n" % (
        ts, socket.inet_ntoa(src), sport, socket.inet_ntoa(dst), dport, ulen))
