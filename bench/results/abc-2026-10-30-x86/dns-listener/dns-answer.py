#!/usr/bin/env python3
"""Send one probe.test A query and print the first A record, validating the reply."""
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
query = (b"\x5a\x5a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x05probe\x04test\x00\x00\x01\x00\x01")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(query, (host, port))
data, _ = sock.recvfrom(512)

rcode = data[3] & 0x0F
ancount = int.from_bytes(data[6:8], "big")
if rcode != 0 or ancount < 1:
    sys.exit(f"rcode={rcode} ancount={ancount}")


def skip_name(blob, off):
    while True:
        length = blob[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


off = skip_name(data, 12) + 4
off = skip_name(data, off)
rtype = int.from_bytes(data[off:off + 2], "big")
rdlength = int.from_bytes(data[off + 8:off + 10], "big")
rdata = data[off + 10:off + 10 + rdlength]
if rtype != 1 or rdlength != 4:
    sys.exit(f"answer type={rtype} rdlength={rdlength}")
print(".".join(map(str, rdata)))
