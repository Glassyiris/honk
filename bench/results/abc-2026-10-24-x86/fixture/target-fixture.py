#!/usr/bin/env python3
import http.server, socket, struct, threading

BODY = b"x" * 1024

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)
    def log_message(self, *args):
        pass

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def http_worker(port):
    Server(("0.0.0.0", port), Handler).serve_forever()

def udp_echo_worker(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    while True:
        data, peer = s.recvfrom(65535)
        s.sendto(data, peer)

def dns_response(query):
    if len(query) < 12:
        return b""
    off = 12
    while off < len(query) and query[off] != 0:
        off += query[off] + 1
    end = off + 5
    if end > len(query):
        return b""
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.42")
    return header + query[12:end] + answer

def dns_worker(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    while True:
        data, peer = s.recvfrom(4096)
        reply = dns_response(data)
        if reply:
            s.sendto(reply, peer)

for port in (8080, 8001, 8002, 8003, 8004, 8005, 8006):
    threading.Thread(target=http_worker, args=(port,), daemon=True).start()
for port in (53531, 53532, 53533, 53534, 53535, 53536):
    threading.Thread(target=udp_echo_worker, args=(port,), daemon=True).start()
threading.Thread(target=dns_worker, args=(53539,), daemon=True).start()
threading.Event().wait()
