#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import signal
import socket
import ssl
import struct
import sys
import threading

spec = importlib.util.spec_from_file_location('vless_targets', Path(__file__).with_name('vless-current') / 'targets.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
ALLOWED = {'127.0.0.1', '10.10.10.70', '10.10.10.49', '10.10.10.118'}

class Handler(base.Handler):
    def end_headers(self):
        self.send_header('X-Bench-Peer', self.client_address[0])
        super().end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

class Server(base.Server):
    def verify_request(self, request, address):
        return address[0] in ALLOWED


def udp_loop(sock, dns=False):
    while True:
        try:
            data, peer = sock.recvfrom(65535)
        except OSError:
            return
        if peer[0] not in ALLOWED:
            continue
        if not dns:
            reply = b'HB1' + socket.inet_aton(peer[0]) + data
        else:
            if len(data) < 12 or data[4:6] != b'\0\1':
                continue
            end = 12
            while end < len(data) and 0 < data[end] < 64:
                end += 1 + data[end]
            if end + 5 > len(data) or data[end] != 0:
                continue
            end += 5
            qtype = struct.unpack('!H', data[end-4:end-2])[0]
            address = socket.inet_aton('10.10.10.70') if qtype == 1 else socket.inet_pton(socket.AF_INET6, '::ffff:10.10.10.70')
            if qtype not in (1, 28):
                continue
            reply = data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + data[12:end]
            reply += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 60, len(address)) + address
        try:
            sock.sendto(reply, peer)
        except OSError:
            pass


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(config['cert'], config['key'])
    servers, sockets = [], []
    try:
        for tls, ports in ((False, config['http_ports']), (True, config['https_ports'])):
            for port in ports:
                server = Server((config['bind'], port), Handler)
                servers.append(server)
                if tls:
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                threading.Thread(target=server.serve_forever, daemon=True).start()
        for port in config['udp_ports'] + [config['dns_port']]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((config['bind'], port))
            sockets.append(sock)
            threading.Thread(target=udp_loop, args=(sock, port == config['dns_port']), daemon=True).start()
        def stop(*_):
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        print('Datapath targets ready', flush=True)
        signal.pause()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for sock in sockets:
            sock.close()

if __name__ == '__main__':
    main()
