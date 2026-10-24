#!/usr/bin/env python3
"""Passive AF_PACKET counter: TCP SYNs without ACK and UDP source ports.

Usage: conn-count.py IFACE PORT SECONDS
Prints JSON with tcp_syn and udp_src_ports counts.
"""
import json
import socket
import struct
import sys
import time

iface, port, duration = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sock.bind((iface, 0))
sock.settimeout(0.5)
syns = 0
udp_src = set()
end = time.time() + duration
while time.time() < end:
    try:
        frame, _ = sock.recvfrom(65535)
    except TimeoutError:
        continue
    if len(frame) < 34:
        continue
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl + 4:
        continue
    proto = ip[9]
    src = socket.inet_ntoa(ip[12:16])
    if proto == 6:
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport = struct.unpack("!HH", tcp[:4])
        flags = tcp[13]
        if dport != port or sport == port:
            continue
        if flags & 0x02 and not flags & 0x10:
            syns += 1
    elif proto == 17:
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        sport, dport = struct.unpack("!HH", udp[:4])
        if dport != port or sport == port:
            continue
        udp_src.add((src, sport))
print(json.dumps({"tcp_syn": syns, "udp_src_ports": len(udp_src)}))
