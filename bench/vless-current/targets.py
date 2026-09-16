#!/usr/bin/env python3
import http.server
import json
import signal
import socket
import ssl
import sys
import threading

BLOCK = b'Z' * 65536

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass
    def do_GET(self):
        try:
            length = 1024 if self.path == '/' else int(self.path.removeprefix('/bytes/'))
            if length < 0 or length > 1024 * 1024 * 1024:
                raise ValueError('bounded body length')
        except ValueError:
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header('Content-Length', str(length))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            while length:
                chunk = min(length, len(BLOCK))
                self.wfile.write(BLOCK[:chunk])
                length -= chunk
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def shutdown_request(self, request):
        if isinstance(request, ssl.SSLSocket):
            # Send close_notify before TCP shutdown; the peer may close without acknowledging it.
            try:
                request.settimeout(0.5)
                request = request.unwrap()
            except (OSError, ssl.SSLError):
                pass
        super().shutdown_request(request)

if __name__ == '__main__':
    config = json.load(open(sys.argv[1]))
    servers = []
    for port, tls in [(config['http'], False), (config['https'], True)]:
        server = Server(('127.0.0.1', port), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(config['cert'], config['key'])
            server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', config['udp']))
    def echo():
        while True:
            data, peer = udp.recvfrom(65535)
            udp.sendto(data, peer)
    threading.Thread(target=echo, daemon=True).start()
    def stop(*_):
        for server in servers:
            server.shutdown()
            server.server_close()
        udp.close()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print('VLESS benchmark targets ready', flush=True)
    signal.pause()
