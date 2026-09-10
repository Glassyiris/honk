#!/usr/bin/env python3
"""Owned lab namespaces, real honk binaries, and paired new/cached-flow checks."""
import argparse
import ctypes
import fcntl
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

PAYLOAD = b'honk-cse-real-packet\n'
PORTS = {'direct': 18080, 'proxy': 18081, 'block': 18082, 'early': 18083}
SERVER4 = os.environ.get('CSE_SERVER4', '198.19.241.2')
SERVER6 = os.environ.get('CSE_SERVER6', 'fdc5:241::2')
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
SYS_BPF = {'x86_64': 321, 'aarch64': 280}[platform.machine()]


def command(*args, check=True, netns=None):
    result = subprocess.run(
        [str(a) for a in args], capture_output=True, text=True,
        pass_fds=() if netns is None else (netns,),
        preexec_fn=None if netns is None else lambda: os.setns(netns, 0),
    )
    if check and result.returncode:
        raise RuntimeError(f'{args}: {result.returncode}: {result.stderr.strip()}')
    return result


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def bpf(cmd, data):
    raw = ctypes.create_string_buffer(data, max(144, len(data)))
    result = LIBC.syscall(SYS_BPF, cmd, ctypes.byref(raw), len(raw))
    if result < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return result, raw.raw


def tc_stats():
    result, current = {}, 0
    while True:
        try:
            _, data = bpf(11, struct.pack('<III', current, 0, 0))
        except OSError as error:
            if error.errno == 2:
                break
            raise
        current = struct.unpack_from('<I', data, 4)[0]
        try:
            fd, _ = bpf(13, struct.pack('<III', current, 0, 0))
        except OSError as error:
            if error.errno == 2:
                continue
            raise
        try:
            info = ctypes.create_string_buffer(256)
            bpf(15, struct.pack('<IIQ', fd, len(info), ctypes.addressof(info)))
            if struct.unpack_from('<I', info.raw)[0] == 3:
                runtime, calls = struct.unpack_from('<QQ', info.raw, 192)
                result[str(current)] = {'name': info.raw[64:80].split(b'\0')[0].decode(), 'runtime_ns': runtime, 'calls': calls}
        finally:
            os.close(fd)
    return result


def owned_tc_programs(pid):
    available = tc_stats()
    owned = set()
    for entry in (Path('/proc') / str(pid) / 'fdinfo').iterdir():
        try:
            for line in entry.read_text().splitlines():
                if line.startswith('prog_id:'):
                    owned.add(line.split()[1])
        except FileNotFoundError:
            continue
    return owned.intersection(available)


def tc_delta(before, after):
    owned = set(os.environ.get('CSE_TC_IDS', '').split(','))
    return {
        pid: {'name': info['name'],
              'runtime_ns': info['runtime_ns'] - before.get(pid, {}).get('runtime_ns', 0),
              'calls': info['calls'] - before.get(pid, {}).get('calls', 0)}
        for pid, info in after.items()
        if pid in owned
    }


class Http(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()
    def do_GET(self):
        body = json.dumps({'payload': PAYLOAD.decode(), 'peer': self.client_address[:2]}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass


class LocalHttp(http.server.ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = 'cse.test'
        self.server_port = self.server_address[1]


class Http6(LocalHttp):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def dns_reply(packet):
    pos = 12
    while packet[pos]:
        pos += packet[pos] + 1
    pos += 1
    qtype, qclass = struct.unpack_from('!HH', packet, pos)
    question = packet[12:pos + 4]
    answer = ipaddress.ip_address(SERVER6 if qtype == 28 else SERVER4).packed
    if qclass != 1 or qtype not in (1, 28):
        answer = b''
    header = packet[:2] + struct.pack('!5H', 0x8180, 1, bool(answer), 0, 0)
    return header + question + (b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 30, len(answer)) + answer if answer else b'')


def udp_server(sock, port):
    while True:
        data, address = sock.recvfrom(4096)
        reply = dns_reply(data) if port == 53000 else json.dumps({'payload': data.decode(), 'peer': address[:2]}).encode()
        sock.sendto(reply, address)


def serve():
    servers = []
    for family in (socket.AF_INET, socket.AF_INET6):
        for port in PORTS.values():
            cls = Http6 if family == socket.AF_INET6 else LocalHttp
            srv = cls(('::' if family == socket.AF_INET6 else '0.0.0.0', port), Http)
            servers.append(srv)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        for port in [*PORTS.values(), 53000]:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', port))
            threading.Thread(target=udp_server, args=(sock, port), daemon=True).start()
    print('CSE_SERVERS_READY', flush=True)
    signal.pause()


def query_dns(family, tcp):
    target = SERVER6 if family == 6 else SERVER4
    packet = struct.pack('!6H', 0x4353, 0x100, 1, 0, 0, 0) + b'\x03cse\x04test\0' + struct.pack('!HH', 28 if family == 6 else 1, 1)
    with socket.socket(socket.AF_INET6 if family == 6 else socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.connect((target, 53))
        if tcp:
            sock.sendall(struct.pack('!H', len(packet)) + packet)
            stream = sock.makefile('rb')
            size = struct.unpack('!H', stream.read(2))[0]
            reply = stream.read(size)
        else:
            sock.send(packet)
            reply = sock.recv(4096)
    assert reply[:2] == packet[:2] and struct.unpack_from('!H', reply, 6)[0] == 1
    assert reply.endswith(ipaddress.ip_address(target).packed), reply.hex()


def collect(samples, include_block=True, include_dns=True):
    rows = []
    for family in (4, 6):
        target = SERVER6 if family == 6 else SERVER4
        for protocol in ('tcp', 'udp'):
            for action, port in PORTS.items():
                if action == 'block' and include_block:
                    with socket.socket(socket.AF_INET6 if family == 6 else socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as sock:
                        sock.settimeout(0.3)
                        outcome = 'close'
                        try:
                            sock.connect((target, port))
                            sock.sendall(PAYLOAD if protocol == 'udp' else b'GET / HTTP/1.1\r\nHost: cse.test\r\n\r\n')
                            assert not sock.recv(4096), f'{family}/{protocol}/block forwarded application data'
                        except TimeoutError:
                            outcome = 'timeout'
                        except ConnectionResetError:
                            outcome = 'reset'
                    rows.append({'family': family, 'protocol': protocol, 'action': action, 'blocked': True, 'outcome': outcome})
                    continue
                for flow in ('new', 'cached'):
                    elapsed = []
                    cpu_before = {}
                    connection = None
                    try:
                        for index in range(samples + 1):
                            if index == 1:
                                if include_block:
                                    cpu_before = tc_stats()
                                case_start = time.monotonic_ns()
                            if connection is None:
                                if protocol == 'tcp':
                                    connection = http.client.HTTPConnection(target, port, timeout=2)
                                else:
                                    connection = socket.socket(socket.AF_INET6 if family == 6 else socket.AF_INET, socket.SOCK_DGRAM)
                                    connection.settimeout(2)
                                    connection.connect((target, port))
                            start = time.monotonic_ns()
                            if protocol == 'tcp':
                                connection.request('GET', '/')
                                response = connection.getresponse()
                                assert response.status == 200
                                reply = json.loads(response.read())
                                source_port = connection.sock.getsockname()[1]
                            else:
                                connection.send(PAYLOAD)
                                reply = json.loads(connection.recv(4096))
                                source_port = connection.getsockname()[1]
                            assert reply['payload'] == PAYLOAD.decode()
                            if include_block:
                                assert (reply['peer'][1] != source_port) == (action == 'proxy'), (family, protocol, action, source_port, reply)
                            if index:
                                elapsed.append(time.monotonic_ns() - start)
                            if flow == 'new':
                                connection.close()
                                connection = None
                    except Exception as error:
                        raise RuntimeError(f'{family}/{protocol}/{action}/{flow}: {error}') from error
                    finally:
                        if connection is not None:
                            connection.close()
                    case_elapsed = time.monotonic_ns() - case_start
                    counters = tc_delta(cpu_before, tc_stats()) if include_block else {}
                    if include_block:
                        assert sum(value['calls'] for value in counters.values()) > 0, 'no owned TC executions were observed'
                    rows.append({'family': family, 'protocol': protocol, 'action': action, 'flow': flow, 'latency_ns': elapsed, 'tc': counters, 'case_elapsed_ns': case_elapsed, 'requests_per_second': samples * 1e9 / case_elapsed, 'measured_new_flow_fraction': int(flow == 'new')})
        if include_dns:
            for tcp in (False, True):
                query_dns(family, tcp)
                rows.append({'family': family, 'protocol': 'dns-tcp' if tcp else 'dns-udp', 'answered': True})
    return rows


def stop_owned(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError('owned child required SIGKILL; cleanup must be audited')
    if process.returncode not in (0, -signal.SIGTERM):
        raise RuntimeError(f'owned child exited {process.returncode}')


def process_identity(pid):
    proc = Path('/proc') / str(pid)
    image = (proc / 'exe').stat()
    return (os.readlink(proc / 'exe'), image.st_dev, image.st_ino, (proc / 'stat').read_text().rsplit(') ', 1)[1].split()[19])


def verify_local_proxy(pid):
    proc = Path('/proc') / str(pid)
    assert Path('/root/.config/mihomo/config.yaml').read_bytes().strip() == b'mixed-port: 7890'
    targets = []
    for fd in (proc / 'fd').iterdir():
        try:
            targets.append(os.readlink(fd))
        except OSError:
            continue
    assert not any('/dev/net/tun' in target for target in targets)
    inodes = {target[8:-1] for target in targets if target.startswith('socket:[')}
    listeners = []
    for table in ('tcp', 'tcp6', 'udp', 'udp6'):
        for line in (proc / 'net' / table).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[9] in inodes and fields[3] in ('0A', '07'):
                listeners.append(fields[1])
    assert listeners and all(address == '0100007F:1ED2' for address in listeners), listeners
    return process_identity(pid)


def tun_bridge(netns, name):
    saved = os.open('/proc/thread-self/ns/net', os.O_RDONLY)
    descriptors = []
    def create(interface):
        fd = os.open('/dev/net/tun', os.O_RDWR)
        descriptors.append(fd)
        fcntl.ioctl(fd, 0x400454CA, struct.pack('16sH22x', interface.encode(), 0x1001))
        return fd
    try:
        host = create(name)
        try:
            os.setns(netns, 0)
            peer = create('csegre')
        finally:
            try:
                os.setns(saved, 0)
            except OSError:
                os.abort()
        print('CSE_TUN_CREATED', flush=True)
        assert sys.stdin.readline().strip() == 'go'
        print('CSE_TUN_READY', flush=True)
        with selectors.DefaultSelector() as selector:
            selector.register(host, selectors.EVENT_READ, peer)
            selector.register(peer, selectors.EVENT_READ, host)
            while True:
                for key, _ in selector.select():
                    packet = os.read(key.fd, 65536)
                    assert packet and os.write(key.data, packet) == len(packet)
    finally:
        for fd in descriptors:
            os.close(fd)
        os.close(saved)


def run(args):
    global SERVER4, SERVER6
    def interrupted(signum, _frame):
        raise InterruptedError(f'lab interrupted by signal {signum}')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    directory = Path(args.directory).resolve()
    directory.mkdir(exist_ok=True)
    assert directory.stat().st_mode & 0o077 == 0, 'run directory must be private'
    script_hash = digest(__file__)
    script_path = directory / f'runner-{script_hash}.py'
    script_path.write_bytes(Path(__file__).read_bytes())
    lock = open('/tmp/honk-cse-live.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    marker = f'cse-{os.getpid()}'
    client_ns, server_ns = marker + '-c', marker + '-s'
    host_client, host_server = 'cseh0', 'cseh1'
    local_proxy = verify_local_proxy(args.local_proxy_pid) if args.local_proxy_pid else None
    owned_links, owned_ns, children, firewall = [], [], [], []
    backup, original_active, restore_errors, records = {}, False, [], []
    ns_fds, complete = {}, False
    expected = {'x86_64': '9404576b8e327d05341fd0b4df72113fabfd8ee97055427e837ac8f9847966f9', 'aarch64': '12e2bba768ea7fcf38fc4f35f57a94a7c5671a76a7f0453cab98a659a34b4a9c'}
    original_binary = '/usr/bin/honk-core' if args.arch == 'aarch64' else '/usr/local/bin/honk-core'
    assert digest(original_binary) == expected[args.arch], 'original engine identity changed'
    for path in ('/etc/honk/config.dae', '/etc/config/honk', '/etc/honk/api.secret', '/etc/honk/config.d/99-openwrt.dae', '/etc/crontabs/root'):
        file = Path(path)
        if file.exists():
            backup[path] = (file.read_bytes(), file.stat().st_mode & 0o7777)
    checkpoint = directory / 'protected-checkpoint.json'
    checkpoint.write_text(json.dumps({path: {'contents_hex': contents.hex(), 'mode': mode} for path, (contents, mode) in backup.items()}))
    checkpoint.chmod(0o600)
    original4 = Path('/proc/sys/net/ipv4/ip_forward').read_text()
    ipv6_root = Path('/proc/sys/net/ipv6/conf')
    original6 = (ipv6_root / 'all/forwarding').read_text()
    ipv6_settings = {
        str(interface / key): (interface / key).read_text()
        for interface in ipv6_root.iterdir() if interface.name != 'all'
        for key in ('forwarding', 'accept_ra')
    }
    stat_fd = None
    try:
        for name in (host_client, host_server, 'cseg0', 'cseg1'):
            assert command('ip', 'link', 'show', name, check=False).returncode != 0, f'foreign interface {name}'
        if args.arch == 'aarch64':
            original_active = command('/etc/init.d/honk', 'running', check=False).returncode == 0
            assert original_active, 'expected active original procd engine'
            command('/etc/init.d/honk', 'stop')
        else:
            assert command('systemctl', 'is-active', '--quiet', 'honk-core.service', check=False).returncode != 0
        for _ in range(50):
            foreign = []
            for entry in Path('/proc').iterdir():
                if entry.name.isdecimal():
                    try:
                        executable = os.readlink(entry / 'exe')
                    except OSError:
                        continue
                    basename = Path(executable).name
                    if 'honk' in basename or basename in ('dae', 'sing-box', 'mihomo'):
                        if args.local_proxy_pid == int(entry.name):
                            assert process_identity(entry.name) == local_proxy
                            continue
                        foreign.append((entry.name, executable))
            if not foreign:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f'foreign engines did not stop: {foreign}')
        if original_active and '/etc/crontabs/root' in backup:
            cron = backup['/etc/crontabs/root'][0]
            Path('/etc/crontabs/root').write_bytes(b'\n'.join(line for line in cron.split(b'\n') if b'honk' not in line))
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
        if original6.strip() != '1':
            for path, value in ipv6_settings.items():
                if path.endswith('/accept_ra') and value.strip() == '1' and Path(path).exists():
                    Path(path).write_text('2')
            (ipv6_root / 'all/forwarding').write_text('1')
        for ns, host_if, peer, network, net6 in [(client_ns, host_client, 'csec0', '198.19.240', 'fdc5:240'), (server_ns, host_server, 'cses0', '198.19.241', 'fdc5:241')]:
            command('ip', 'netns', 'add', ns)
            owned_ns.append(ns)
            ns_fds[ns] = os.open('/var/run/netns/' + ns, os.O_RDONLY)
            command('ip', 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', peer)
            link_id = json.loads(command('ip', '-j', 'link', 'show', host_if).stdout)[0]['ifindex']
            owned_links.append((host_if, link_id))
            command('ip', 'link', 'set', peer, 'netns', ns)
            command('ip', 'link', 'set', host_if, 'up')
            command('ip', 'addr', 'add', network + '.1/24', 'dev', host_if)
            command('ip', '-6', 'addr', 'add', net6 + '::1/64', 'dev', host_if, 'nodad')
            Path(f'/proc/sys/net/ipv6/conf/{host_if}/forwarding').write_text('1')
            for cmd in [('link', 'set', 'lo', 'up'), ('link', 'set', peer, 'up'), ('addr', 'add', network + '.2/24', 'dev', peer), ('-6', 'addr', 'add', net6 + '::2/64', 'dev', peer, 'nodad'), ('route', 'add', 'default', 'via', network + '.1'), ('-6', 'route', 'add', 'default', 'via', net6 + '::1')]:
                command('ip', '-n', ns, *cmd)
        if args.link in ('gre', 'tun'):
            for ns, underlay, peer, tunnel, base, inner, net6 in [
                (client_ns, host_client, 'csec0', 'cseg0', '198.19.240', '198.19.242', 'fdc5:242'),
                (server_ns, host_server, 'cses0', 'cseg1', '198.19.241', '198.19.243', 'fdc5:243'),
            ]:
                if args.link == 'gre':
                    command('ip', 'tunnel', 'add', tunnel, 'mode', 'gre', 'local', base + '.1', 'remote', base + '.2', 'dev', underlay, 'ttl', '64')
                    command('ip', '-n', ns, 'tunnel', 'add', 'csegre', 'mode', 'gre', 'local', base + '.2', 'remote', base + '.1', 'dev', peer, 'ttl', '64')
                else:
                    bridge_log_path = directory / f'{tunnel}-bridge.log'
                    bridge_log = open(bridge_log_path, 'w')
                    bridge = subprocess.Popen([sys.executable, str(script_path), 'bridge', str(ns_fds[ns]), tunnel], pass_fds=(ns_fds[ns],), stdin=subprocess.PIPE, stdout=bridge_log, stderr=subprocess.STDOUT)
                    children.append(bridge)
                    for _ in range(100):
                        assert bridge.poll() is None, f'TUN bridge failed: {bridge_log_path}'
                        if 'CSE_TUN_CREATED' in bridge_log_path.read_text():
                            break
                        time.sleep(0.05)
                    else:
                        raise RuntimeError('TUN bridge readiness timeout')
                tunnel_id = json.loads(command('ip', '-j', 'link', 'show', tunnel).stdout)[0]['ifindex']
                owned_links.append((tunnel, tunnel_id))
                command('ip', 'link', 'set', tunnel, 'up')
                command('ip', 'addr', 'add', inner + '.1/24', 'dev', tunnel)
                command('ip', '-6', 'addr', 'add', net6 + '::1/64', 'dev', tunnel, 'nodad')
                Path(f'/proc/sys/net/ipv6/conf/{tunnel}/forwarding').write_text('1')
                for cmd in [('link', 'set', 'csegre', 'up'), ('addr', 'add', inner + '.2/24', 'dev', 'csegre'), ('-6', 'addr', 'add', net6 + '::2/64', 'dev', 'csegre', 'nodad'), ('route', 'replace', 'default', 'via', inner + '.1'), ('-6', 'route', 'replace', 'default', 'via', net6 + '::1')]:
                    command('ip', '-n', ns, *cmd)
                if args.link == 'tun':
                    bridge.stdin.write(b'go\n')
                    bridge.stdin.flush()
                    for _ in range(100):
                        assert bridge.poll() is None, f'TUN bridge failed: {bridge_log_path}'
                        if 'CSE_TUN_READY' in bridge_log_path.read_text():
                            break
                        time.sleep(0.05)
                    else:
                        raise RuntimeError('TUN forwarding readiness timeout')
            host_client, host_server = 'cseg0', 'cseg1'
            SERVER4, SERVER6 = '198.19.243.2', 'fdc5:243::2'
            os.environ.update(CSE_SERVER4=SERVER4, CSE_SERVER6=SERVER6)
        for _ in range(100):
            addresses = []
            for interface, ns in [(host_client, None), (host_server, None), ('csec0', client_ns), ('cses0', server_ns)]:
                flags = command('ip', '-j', '-6', 'addr', 'show', 'dev', interface, netns=None if ns is None else ns_fds[ns]).stdout
                addresses.extend(info for link in json.loads(flags) for info in link['addr_info'])
            assert not any(info.get('dadfailed') for info in addresses), 'owned IPv6 address failed DAD'
            if not any(info.get('tentative') for info in addresses):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError('owned IPv6 address readiness timeout')
        if command('nft', 'list', 'chain', 'inet', 'fw4', 'forward', check=False).returncode == 0:
            for source, dest in [(host_client, host_server), (host_server, host_client)]:
                command('nft', 'insert', 'rule', 'inet', 'fw4', 'forward', 'iifname', source, 'oifname', dest, 'accept', 'comment', '"' + marker + '"')
            ingress_interfaces = {name for name, _ in owned_links}
            for interface in ingress_interfaces:
                command('nft', 'insert', 'rule', 'inet', 'fw4', 'input', 'iifname', interface, 'accept', 'comment', '"' + marker + '"')
            snapshot = json.loads(command('nft', '-j', '-a', 'list', 'table', 'inet', 'fw4').stdout)
            firewall = [item['rule'] for item in snapshot['nftables'] if 'rule' in item and item['rule'].get('comment') == marker]
            assert len(firewall) == 2 + len(ingress_interfaces)
        server_log = open(directory / 'servers.log', 'w')
        server = subprocess.Popen(['ip', 'netns', 'exec', server_ns, sys.executable, str(script_path), 'serve'], stdout=server_log, stderr=subprocess.STDOUT)
        children.append(server)
        for _ in range(100):
            if 'CSE_SERVERS_READY' in (directory / 'servers.log').read_text():
                break
            assert server.poll() is None, 'local packet server failed'
            time.sleep(0.05)
        else:
            raise RuntimeError('packet server readiness timeout')
        singbox = args.singbox
        sbconfig = {'log': {'level': 'warn'}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': 39080}], 'outbounds': [{'type': 'direct', 'routing_mark': 256}]}
        (directory / 'socks.json').write_text(json.dumps(sbconfig))
        socks_log = open(directory / 'socks.log', 'w')
        socks = subprocess.Popen([singbox, 'run', '-c', str(directory / 'socks.json')], stdout=socks_log, stderr=subprocess.STDOUT)
        children.append(socks)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', 39080), 0.1):
                    break
            except OSError:
                assert socks.poll() is None, 'local SOCKS server failed'
                time.sleep(0.05)
        else:
            raise RuntimeError('SOCKS readiness timeout')
        # Existing servers on every action port establish the blocked-path control.
        command(sys.executable, str(script_path), 'client', '--samples', '1', '--preflight', netns=ns_fds[server_ns])
        command(sys.executable, str(script_path), 'client', '--samples', '1', '--preflight')
        command('ip', 'netns', 'exec', client_ns, sys.executable, str(script_path), 'client', '--samples', '1', '--preflight')
        stat_fd, _ = bpf(32, struct.pack('<I', 0))
        print('CSE_LIVE_READY', flush=True)
        for pair in range(args.pairs):
            order = ('baseline', 'candidate') if pair % 2 == 0 else ('candidate', 'baseline')
            for arm in order:
                binary = directory / f'honk-{arm}-{args.arch}'
                config = f'''global {{
 lan_interface: {host_client}
 wan_interface: {host_server}
 dial_mode: ip
 nfqueue_enable: false
 auto_config_kernel_parameter: false
 disable_waiting_network: true
 data_dir: '{directory}/data'
 tcp_check_url: 'http://{SERVER4}:18080/'
 udp_check_dns: '{SERVER4}:53000'
 check_interval: 3600s
}}
node {{
 local: 'socks5://127.0.0.1:39080'
}}
group {{
 proxy {{
  filter: name(local)
  policy: fixed(0)
 }}
}}
dns {{
 upstream {{
  local: 'udp://{SERVER4}:53000'
 }}
 routing {{
  request {{
   fallback: local
  }}
 }}
}}
routing {{
 dport(18083) -> direct(must)
'''
                for bit in range(64):
                    config += f' dip(198.18.{bit}.1, 2001:db8:ffff::{bit:x}) -> block\n sip(198.18.{bit}.2, 2001:db8:fffe::{bit:x}) -> block\n mac(02:ff:00:00:00:{bit:02x}) -> block\n'
                config += ''' dport(18080) -> direct(must)
 dport(18081) -> proxy(must)
 dport(18082) -> block
 fallback: direct
}
experimental {
 clash_api {
  external_controller: '127.0.0.1:39990'
  secret: 'cse-local-test'
 }
}
'''
                config_path = directory / 'traffic.dae'
                config_path.write_text(config)
                logfile = directory / f'{pair}-{arm}.log'
                engine_log = open(logfile, 'w')
                engine = subprocess.Popen(['taskset', '-c', '2,3', str(binary), '-c', str(config_path), '--bpf-pin-root', '/sys/fs/bpf'], stdout=engine_log, stderr=subprocess.STDOUT)
                children.append(engine)
                for _ in range(200):
                    assert engine.poll() is None, f'engine startup failed: {logfile}'
                    try:
                        conn = http.client.HTTPConnection('127.0.0.1', 39990, timeout=0.2)
                        conn.request('GET', '/version', headers={'Authorization': 'Bearer cse-local-test'})
                        response = conn.getresponse()
                        assert response.status == 200
                        response.read()
                        conn.close()
                        if 'eBPF datapath admission opened after listener publication' not in logfile.read_text():
                            time.sleep(0.05)
                            continue
                        break
                    except (OSError, http.client.HTTPException):
                        time.sleep(0.05)
                else:
                    raise RuntimeError('engine readiness timeout')
                owned_ids = owned_tc_programs(engine.pid)
                assert owned_ids, 'cannot identify owned TC programs'
                os.environ['CSE_TC_IDS'] = ','.join(sorted(owned_ids))
                for role, netns in [('LAN', ns_fds[client_ns]), ('WAN', None)]:
                    before = tc_stats()
                    started = time.monotonic_ns()
                    output = command('taskset', '-c', '0', sys.executable, str(script_path), 'client', '--samples', str(args.samples), netns=netns).stdout
                    elapsed = time.monotonic_ns() - started
                    after = tc_stats()
                    deltas = tc_delta(before, after)
                    records.append({'pair': pair, 'arm': arm, 'role': role, 'link': args.link, 'binary_sha256': digest(binary), 'config_sha256': digest(config_path), 'pid': engine.pid, 'elapsed_ns': elapsed, 'tc': deltas, 'rows': json.loads(output)})
                    print(json.dumps({'pair': pair, 'arm': arm, 'role': role, 'checks': len(records[-1]['rows'])}), flush=True)
                stop_owned(engine)
                children.remove(engine)
                engine_log.close()
                (directory / 'live-partial.json').write_text(json.dumps(records, indent=2))
        complete = True
    except Exception:
        diagnostics = {}
        for name, fd in [('host', None), *ns_fds.items()]:
            diagnostics[name] = {
                'neighbors': command('ip', '-j', '-6', 'neigh', netns=fd, check=False).stdout,
                'addresses': command('ip', '-j', 'addr', netns=fd, check=False).stdout,
                'ipv4_routes': command('ip', '-j', 'route', 'show', 'table', 'all', netns=fd, check=False).stdout,
                'ipv6_routes': command('ip', '-j', '-6', 'route', 'show', 'table', 'all', netns=fd, check=False).stdout,
                'rules': command('ip', '-j', 'rule', netns=fd, check=False).stdout,
            }
        (directory / 'failure-network.json').write_text(json.dumps(diagnostics, indent=2))
        raise
    finally:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, signal.SIG_IGN)
        for child in reversed(children):
            try:
                stop_owned(child)
            except Exception as error:
                restore_errors.append(str(error))
        for rule in firewall:
            try:
                current = json.loads(command('nft', '-j', '-a', 'list', 'table', 'inet', 'fw4').stdout)
                matches = [item['rule'] for item in current['nftables'] if 'rule' in item and item['rule'].get('comment') == marker and item['rule'].get('chain') == rule['chain'] and item['rule'].get('expr') == rule['expr']]
                for match in matches:
                    command('nft', 'delete', 'rule', 'inet', 'fw4', rule['chain'], 'handle', match['handle'])
            except Exception as error:
                restore_errors.append(str(error))
        for link, link_id in reversed(owned_links):
            current = command('ip', '-j', 'link', 'show', link, check=False)
            if current.returncode == 0:
                if json.loads(current.stdout)[0]['ifindex'] == link_id:
                    command('ip', 'link', 'del', link)
                else:
                    restore_errors.append(f'foreign replacement interface retained: {link}')
        for ns in reversed(owned_ns):
            named = Path('/var/run/netns') / ns
            if named.exists() and named.stat().st_ino == os.fstat(ns_fds[ns]).st_ino:
                command('ip', 'netns', 'del', ns)
            os.close(ns_fds[ns])
        Path('/proc/sys/net/ipv4/ip_forward').write_text(original4)
        (ipv6_root / 'all/forwarding').write_text(original6)
        for path, value in ipv6_settings.items():
            if Path(path).exists():
                Path(path).write_text(value)
        for path, (contents, mode) in backup.items():
            if not original_active:
                continue
            try:
                Path(path).write_bytes(contents)
                os.chmod(path, mode)
                assert digest(path) == hashlib.sha256(contents).hexdigest()
            except Exception as error:
                restore_errors.append(str(error))
        if original_active:
            try:
                command('/etc/init.d/honk', 'start')
                command('/etc/init.d/honk', 'running')
                for path, (contents, mode) in backup.items():
                    Path(path).write_bytes(contents)
                    os.chmod(path, mode)
                    assert digest(path) == hashlib.sha256(contents).hexdigest()
            except Exception as error:
                restore_errors.append(str(error))
        if stat_fd is not None:
            os.close(stat_fd)
        if local_proxy is not None:
            try:
                assert verify_local_proxy(args.local_proxy_pid) == local_proxy
            except Exception as error:
                restore_errors.append(f'original local proxy changed: {error}')
        if not restore_errors:
            checkpoint.unlink()
        restoration = {'original_active': original_active, 'original_binary_unchanged': digest(original_binary) == expected[args.arch], 'protected_files_restored': [path for path in backup], 'errors': restore_errors}
        (directory / 'restoration.json').write_text(json.dumps(restoration, indent=2))
        (directory / 'live-results.json').write_text(json.dumps({'complete': complete, 'script_sha256': script_hash, 'script_snapshot': script_path.name, 'link': args.link, 'kernel': platform.release(), 'architecture': args.arch, 'pairs': args.pairs, 'samples': args.samples, 'scope': 'real veth/GRE/TUN LAN/WAN TCP/UDP IPv4/IPv6; direct, local SOCKS5 proxy, block and transparent DNS; TUN edges use an isolated packet-copy bridge; source-port preservation distinguishes direct from proxy; BPF TC runtime accounting enabled equally for both arms; per-case new and cached connections, not physical NIC throughput', 'records': records, 'restoration': restoration}, indent=2))
        if restore_errors:
            raise RuntimeError(f'restoration failed: {restore_errors}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='mode', required=True)
    sub.add_parser('serve')
    bridge = sub.add_parser('bridge')
    bridge.add_argument('netns', type=int)
    bridge.add_argument('name')
    client = sub.add_parser('client')
    client.add_argument('--samples', type=int, default=20)
    client.add_argument('--preflight', action='store_true')
    runner = sub.add_parser('run')
    runner.add_argument('--directory', required=True)
    runner.add_argument('--arch', choices=['x86_64', 'aarch64'], required=True)
    runner.add_argument('--singbox', required=True)
    runner.add_argument('--pairs', type=int, default=3)
    runner.add_argument('--samples', type=int, default=20)
    runner.add_argument('--local-proxy-pid', type=int)
    runner.add_argument('--link', choices=['l2', 'gre', 'tun'], default='l2')
    options = parser.parse_args()
    if options.mode in ('client', 'run') and options.samples < 1:
        parser.error('samples must be positive')
    if options.mode == 'run' and options.pairs < 1:
        parser.error('pairs must be positive')
    if options.mode == 'serve':
        serve()
    elif options.mode == 'bridge':
        tun_bridge(options.netns, options.name)
    elif options.mode == 'client':
        print(json.dumps(collect(options.samples, not options.preflight, not options.preflight)))
    else:
        run(options)
