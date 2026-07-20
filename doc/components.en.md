# honk Component Configuration Reference

Field-level reference for every major component. Companion to [configuration.en.md](./configuration.en.md).

honk is configured in the **dae configuration syntax** — sections like `global { ... }`, `node { ... }`, `group { ... }`, `routing { ... }`, `dns { ... }`, `subscription { ... }`, `experimental { ... }` with `key: value` pairs. See the root examples `config.dae` (full-featured) and `config.min.dae` (minimal).

Source of truth: `crates/honk-config/src/*`, the dae parser in `crates/honk-config/src/parser/`, handlers under `crates/honk-outbound/src/proxy/`, CLI in `crates/honk-core`.

---

## 1. Global (`global { ... }`)

| dae key | Internal field | Default | Meaning |
| ------- | -------------- | --------- | --------- |
| `tproxy_port` | `tproxy_port` | `12345` | Transparent listen port |
| — | `tproxy_mark` | `0x08000000` | fwmark (config / policy routing); not settable in dae syntax |
| `tproxy_port_protect` | `tproxy_port_protect` | `true` | Avoid proxying the TPROXY port itself |
| `pprof_port` | `pprof_port` | `0` | pprof HTTP port; `0` = off |
| `so_mark_from_dae` | `so_mark_from_dae` | `0` | Optional SO_MARK for honk-opened sockets |
| `log_level` | `log_level` | `"info"` | `trace`/`debug`/`info`/`warn`/`error` |
| `disable_waiting_network` | `disable_waiting_network` | `false` | Skip waiting for network readiness |
| `lan_interface` | `lan_interface` | `[]` | LAN ifaces to intercept (comma-separated); empty = none |
| `wan_interface` | `wan_interface` | `[]` | WAN ifaces; `auto` allowed |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | Auto sysctl (root) |
| `tcp_check_url` | `tcp_check_url` | Cloudflare HTTP + 1.1.1.1 + IPv6 | TCP health targets (comma-separated) |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | HTTP method for URL checks |
| `udp_check_dns` | `udp_check_dns` | dns.google / 8.8.8.8 / IPv6 | UDP health DNS targets (comma-separated) |
| `check_interval` | `check_interval_secs` | `30` | Health interval, duration form (e.g. `30s`) |
| `check_tolerance` | `check_tolerance_ms` | `50` | URLTest switch delta, duration form (e.g. `50ms`) |
| `dial_mode` | `dial_mode` | `"domain"` | `ip` / `domain` / `domain+` / `domain++` |
| `lan_tcp_mss` | `lan_tcp_mss` | `0` | Deprecated; parsed only |
| `allow_insecure` | `allow_insecure` | `false` | Global TLS skip-verify fallback |
| `sniffing_timeout` | `sniffing_timeout_ms` | `30` | Sniff timeout, duration form (e.g. `30ms`) |
| `tls_implementation` | `tls_implementation` | `"tls"` | TLS stack name |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | Reserved (REALITY/uTLS deferred) |
| `tls_fragment` | `tls_fragment` | `false` | TLS ClientHello fragment flag |
| `tls_fragment_length` | `tls_fragment_length` | `""` | Fragment length range |
| `tls_fragment_interval` | `tls_fragment_interval` | `""` | Fragment interval range |
| `mptcp` | `mptcp` | `false` | Multipath TCP on dials |
| `bootstrap_resolver` | `bootstrap_resolver` | `""` | Resolve **node hostnames** (avoid loop) |
| `fallback_resolver` | `fallback_resolver` | `"8.8.8.8:53"` | Control-plane fallback DNS |
| `bandwidth_max_tx` / `bandwidth_max_rx` | same | `""` | Bandwidth hints (e.g. `'200 mbps'`) |
| — | `udphop_interval_secs` | `30` | UDP hop interval; not settable in dae syntax |
| — | `connect_timeout_ms` | `3000` | TCP connect timeout; not settable in dae syntax |
| — | `dns_resolve_timeout_ms` | `2000` | Control-plane resolve timeout; not settable in dae syntax |
| — | `relay_idle_timeout_secs` | `300` | Idle relay kill; `0` = off; not settable in dae syntax |
| — | `preconnect_node_count` | `0` | Preconnect count; `0` = auto `min(nodes,8)`; not settable in dae syntax |

```dae
global {
    tproxy_port: 12345
    log_level: info
    lan_interface: podman0
    wan_interface: auto
    dial_mode: domain++
    allow_insecure: false
    auto_config_kernel_parameter: true
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111'
    tcp_check_http_method: HEAD
    udp_check_dns: 'dns.google.com:53,8.8.8.8,2001:4860:4860::8888'
    check_interval: 30s
    check_tolerance: 50ms
    sniffing_timeout: 30ms
    bootstrap_resolver: '223.5.5.5:53'
    fallback_resolver: '8.8.8.8:53'
}
```

### Dial mode detail

| Mode | Sniff | Domain verify | Re-route on sniff |
| ------ | ------- | --------------- | ------------------- |
| `ip` | No | N/A | No |
| `domain` | Yes | Yes (must resolve to dest IP) | No |
| `domain+` | Yes | No | No |
| `domain++` | Forced | No | Yes |

---

## 2. Nodes (`node { ... }`)

In dae syntax a node is a **share link**, optionally prefixed with a tag:

```dae
node {
    iris: 'socks5://10.10.10.1:2077'
    hk1: 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@hk1.example.com:8388#hk1'
    trojan1: 'trojan://secret@example.com:443?sni=example.com#trojan1'
}
```

Every entry needs a tag (`iris:`); untagged share links are **silently dropped** by the parser. The tag overrides the link's `#fragment` name.

### Common fields

The fields below are what a parsed node carries. In dae syntax they are **derived from the share link** (scheme, userinfo, host, query parameters), not written as separate keys.

| Field | Type | Default | Meaning |
| ------- | ------ | --------- | --------- |
| `id` | UUID | random | Stable id |
| `name` | string | **required** | Routing / API name |
| `protocol` | enum | `ss` | See protocol table |
| `address` | string | required* | Host or `host:port` |
| `host` | string | `""` | Explicit host; else from `address` |
| `port` | u16 | `0` | Server port |
| `username` / `password` | string? | null | Auth / UUID / secret |
| `encryption` | string? | null | SS/SSR/VMess cipher |
| `plugin` / `plugin_opts` | string? | null | Plugin name/opts |
| `transport` | string | `"tcp"` | `tcp` / `ws` / `grpc` / … (share-link `type=`/`net`) |
| `tls` | bool | `false` | Enable TLS |
| `sni` | string? | null | TLS SNI (share-link `sni=`) |
| `skip_cert_verify` | bool | `false` | Insecure TLS (share-link `allowInsecure=1`/`insecure=1`) |
| `network` | string? | null | V2Ray-style network hint |
| `ws_path` / `ws_host` | string? | null | WebSocket (share-link `path=`/`host=`) |
| `grpc_service` | string? | null | gRPC service name (`serviceName=`) |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 |
| `tuic_uuid` / `tuic_password` / `tuic_congestion` | string? | null | TUIC |
| `juicity_uuid` / `juicity_password` | string? | null | Juicity |
| `anytls_password` | string? | null | AnyTLS secret |
| `anytls_min_idle_session` | usize? | null | Pool min idle sessions (`min_idle_session=`) |
| `anytls_idle_session_check_interval` | u64? | null | Idle check period, s (`idle_session_check_interval=`) |
| `anytls_idle_session_timeout` | u64? | null | Idle eviction, s (`idle_session_timeout=`) |
| `mux` | bool | `false` | h2mux multiplexing; **not settable from a share link / dae syntax** |
| `mark` | u32? | null | Outbound SO_MARK |
| `tags` | string[] | `[]` | Labels |
| `subscription_id` / `group_id` | UUID? | null | Ownership metadata |
| `created_at` / `updated_at` | datetime | now | Metadata |

\* Validation requires non-empty `name` and non-empty `address` or `host`.

### Protocols

| Value | Aliases | TCP | UDP | Notes |
| ------- | --------- | ----- | ----- | ------- |
| `ss` | `shadowsocks` | Yes | Yes | AEAD + `2022-blake3-*` |
| `ssr` | `shadowsocksr` | Yes | No | `origin` + limited obfs; advanced proto partial |
| `trojan` | | Yes | Yes | TLS; WS/gRPC/h2mux via transport |
| `trojan-go` | | Yes | No | Own mux path |
| `vmess` | | Yes | No | AEAD; WS/gRPC/h2mux |
| `vless` | | Yes | No | Header UDP exists in tests only |
| `socks5` | | Yes | Yes | UDP ASSOCIATE |
| `http` | | Yes* | — | Mapped through direct-style dial |
| `hysteria2` | | Yes | Yes | Real QUIC/H3; salamander; BBR (no brutal) |
| `tuic` | | Yes | Yes | TUIC v5 / quinn |
| `juicity` | | Yes | Yes | quinn bi-stream UDP |
| `anytls` | | Yes | Yes | Session pool + UoT v2 |

Built-in **`direct`** node is injected at load (not required in config).

### Protocol-specific tips

**Shadowsocks 2022**

- Methods: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`
- Password: base64 PSK — 16 bytes for aes-128-gcm, 32 bytes otherwise

**Trojan / VMess / VLESS transport**

Transport options come from share-link query parameters (`type=ws|grpc`, `sni=`, `host=`, `path=`, `serviceName=`):

```dae
node {
    trojan_ws: 'trojan://secret@example.com:443?type=ws&sni=example.com&host=example.com&path=/path#trojan_ws'
    trojan_grpc: 'trojan://secret@example.com:443?type=grpc&serviceName=GunService#trojan_grpc'
}
```

`mux = true` (h2mux) exists in the node schema but cannot be expressed in dae syntax today.

**AnyTLS pool**

Pool tuning comes from share-link query parameters:

```dae
node {
    anytls1: 'anytls://secret@example.com:443?sni=example.com&min_idle_session=3&idle_session_check_interval=30s&idle_session_timeout=30s#anytls1'
}
```

**Hysteria2 / TUIC / Juicity**

Prefer share links; the `hy2_*` / `tuic_*` / `juicity_*` fields are derived from them. QUIC ALPN/congestion follow handler defaults (Hy2 uses BBR).

### Share-link schemes

| Scheme | Notes |
| -------- | ------- |
| `ss://` | SIP002 |
| `ssr://` | base64 parameter blob |
| `vmess://` | base64 JSON (v2rayN) |
| `vless://` / `trojan://` / `trojan-go://` | query params for transport/TLS |
| `anytls://` | pool params in query |
| `hysteria2://` / `tuic://` / `juicity://` | QUIC family |
| `socks5://` / `http://` / `https://` | simple |

Chain `a -> b` parses **first hop only**. Name from `#fragment` or `{scheme}-{host}`.

---

## 3. Groups (`group { ... }`)

```dae
group {
    hk {
        filter: name(keyword: 'hk')
        policy: min_moving_avg
        final: iris
    }
    proxy {
        filter: group('hk')
        filter: name('direct-out')
        policy: select
        default: 'hk'
        final: direct-out
    }
}
```

| dae key | Internal field | Default | Meaning |
| ------- | -------------- | --------- | --------- |
| (section name) | `name` | **required** | Outbound tag in routing |
| `policy` | `policy` | `selector` | Selection policy |
| `filter: name(...)` | `filters` + `nodes` | `[]` | Node filters; resolved to members |
| `filter: group('tag', ...)` | `groups` | `[]` | Nested sub-group tags (`'a', 'b'` or `'a\|b'` forms) |
| `default` | `default` | null | Selector default member tag |
| `final` | `final_outbound` | null | When all members are dead |
| — | `id` | random | Id |
| — | `check_url` | null | Override global TCP check URL; not parsed in dae syntax |
| — | `check_interval` | null | Override interval (s); not parsed in dae syntax |
| — | `tolerance` | `50` | URLTest hysteresis (ms); `0` = any better; not parsed in dae syntax |
| — | `idle_timeout` | null | Stop checks after idle seconds; 0/None = never; not parsed in dae syntax |
| — | `interrupt_connections` | `false` | Drop flows on selection change; not parsed in dae syntax |
| — | `created_at` | now | Metadata |

### Policies

| Canonical | dae spellings | Behavior |
| ----------- | ------------- | ---------- |
| `selector` | `select`, `fixed`, `fixed(0)` | Manual pin; API + cache |
| `urltest` | `min_moving_avg`, `min_avg10`, `min_last_delay` | Lowest latency + tolerance; **TCP/UDP separate** |
| `loadbalance` | `roundrobin`, `round_robin`, `balance` | Per-group RR among alive |
| `fallback` | `fallback` | First alive sticky; no instant failback |

### Filter resolution

1. `filter: group('tag')` → nested tags (`groups`), not node list.
2. `filter: name(...)` filters OR-match into members.
3. No filters and no nested groups → **all nodes**.
4. Nested groups only → **not** all nodes.

### Nested groups

Depth capped at 8; cycles cut at construction with a warning. Dial always resolves to one **leaf** node. Clash `all` shows member tags; health checks expand leaves.

---

## 4. Routing (`routing { ... }`)

Rules are condition functions joined with `&&`, followed by `-> outbound` (optionally `outbound(must)`), in match order, ending with a `fallback:`:

```dae
routing {
    pname(NetworkManager, systemd-resolved) && l4proto(udp) && dport(53) -> direct(must)
    domain(suffix: example.com, geosite: cn) -> proxy
    domain(keyword: m-team) -> direct
    dip(geoip: cn) -> direct(must)
    sip(10.10.10.24/32) -> direct
    dport(22, 80, 443, 8080) -> proxy
    fallback: direct
}
```

`default:` is accepted as an alias of `fallback:`.

### Rule fields (internal schema)

| Field | Type | Default | Meaning |
| ------- | ------ | --------- | --------- |
| `name` | string | auto `rule-N` | Display name |
| condition fields | flattened | | See below |
| `outbound` | string / complex | required | Target (dae syntax: the `->` right-hand side) |
| `priority` | u32 | rule order | Lower = higher priority (dae: line order) |
| `must` | bool | `false` | Non-final must-rule (`-> direct(must)`) |
| `mark` | u32 | `0` | fwmark; `0` = none; not settable in dae syntax |

### Conditions (internal fields)

| Field | Matches |
| ------- | --------- |
| `domain` | Exact domain |
| `domain_suffix` | Suffix |
| `domain_keyword` | Substring |
| `domain_regex` | Regex |
| `ip` | Dest IP/CIDR |
| `source_ip` | Source IP/CIDR |
| `port` / `source_port` | Ports (string forms) |
| `protocol` | `tcp` / `udp` |
| `process_name` | Process (`pname`) |
| `mac` | MAC |
| `geo_ip` | GeoIP codes (`cn`, `private`, …) |
| `geosite` | Geosite codes |
| `ip_version` | IP version |
| `dscp` | DSCP |

Multiple functions on one rule are AND'd with `&&`.

### Condition functions (dae syntax)

| Function | Maps to |
| ---------- | --------- |
| `domain(...)` | domain_* / geosite (via tags) |
| `dip(...)` | `ip` / `geo_ip` |
| `sip(...)` | `source_ip` |
| `dport` / `sport` | ports |
| `l4proto` | `protocol` |
| `pname` | `process_name` |
| `mac` / `dscp` / `ipversion` | same |

`domain` arg tags: bare/`suffix:` → suffix; `keyword:`; `full:`; `regex:`; `geosite:` (`@` → `-`). `dip` args: plain CIDRs or `geoip: code`.

### Complex outbound (not in dae syntax)

A parsed shape `{ type = "or"|"and"|"balancer"|"chain", outbounds = [...] }` exists in the internal schema; **balancer/chain are not fully wired** like simple string outbounds, and dae syntax only writes a plain outbound name after `->`. Prefer group policies.

---

## 5. DNS (`dns { ... }`)

```dae
dns {
    ipversion_prefer: 4
    optimistic_cache: true
    optimistic_cache_ttl: 600
    max_cache_size: 10000
    upstream {
        alidns: 'udp://223.5.5.5:53'
        googledns: 'tcp+udp://dns.google:53' outbound: proxy
    }
    routing {
        request {
            fallback: alidns
        }
    }
}
```

### Top-level

| dae key | Internal field | Default | Meaning |
| ------- | -------------- | --------- | --------- |
| `upstream { ... }` | `upstream` | one `default` @ 223.5.5.5 UDP | Servers |
| `routing { ... }` | `routing` | fallback default | Request routing |
| `ipversion_prefer` | `strategy` | `preferipv4` | Address family (`4`/`6`) |
| `optimistic_cache` | `cache.enabled` | `true` | Cache on/off |
| `optimistic_cache_ttl` | `cache.ttl` | `600` | Cache TTL seconds |
| `max_cache_size` | `cache.max_size` | `10000` | Max entries (must be > 0) |
| `response { ... }` (presence) | `has_response_routing` | `false` | Flag set if dae `response{}` present |

### Upstream

Each upstream is a `name: 'uri'` line; an optional trailing `outbound: tag` sends queries via a node/group.

| Field | Type | Default | Meaning |
| ------- | ------ | --------- | --------- |
| `name` | string | required | Id (the key before `:`) |
| `address` | string | required | `ip:port` or host (from the URI) |
| `protocol` | enum | `udp` | From URI scheme: `udp`/`tcp`/`tls`/`https`/`quic` (`tcp+udp`, `h3`/`http3` aliases) |
| `tls_server_name` | string? | null | DoT/DoH SNI; not settable in dae syntax |
| `bootstrap` | string? | null | Bootstrap DNS; not settable in dae syntax |
| `outbound` | string? | null | Send via node/group (trailing `outbound: tag`) |
| `tags` | string[] | `[]` | Labels; not settable in dae syntax |

**Runtime note:** UDP/TCP work; TLS/HTTPS/QUIC currently fall back toward plain TCP. DNS-over-proxy SOCKS5 UDP is incomplete.

### Routing / rules

| Item | Meaning |
| ------ | --------- |
| `request { fallback: name }` | Upstream if no rule matches (the only request-routing key parsed from dae syntax) |
| `routing.rules[].domain` | Pattern with optional prefix (`suffix:`, `keyword:`, `full:`, `regex:`; bare = full exact) — schema field; per-rule `qname(...) -> upstream` lines are **not** parsed from dae syntax today |
| `routing.rules[].upstream` | Upstream name (schema field) |

### Strategy

Internal values: `preferipv4` | `preferipv6` | `ipv4only` | `ipv6only` | `both`.

dae: `ipversion_prefer: 4|6` (anything else = `preferipv4`).

### Cache

Persistence of DNS answers across restarts: `experimental { cache_file { store_dns: true } }`.

---

## 6. Subscriptions (`subscription { ... }`)

```dae
subscription {
    my_sub: 'https://www.example.com/subscription/link'
}
```

In dae syntax only `name` (the tag) and `url` are settable; the rest is runtime state:

| Field | Type | Default | Meaning |
| ------- | ------ | --------- | --------- |
| `id` | UUID | random | Id |
| `name` | string | required | Display (the tag before `:`) |
| `url` | string | required | Fetch URL |
| `sub_type` | enum | `simple` | `simple`/`clash`/`sip008`/`custom`; not settable in dae syntax |
| `update_interval` | u64 | `86400` | Seconds; `0` = manual; not settable in dae syntax |
| `user_agent` | string? | null | UA; not settable in dae syntax |
| `headers` | `{key,value}[]` | `[]` | Extra headers; not settable in dae syntax |
| `enabled` | bool | `true` | Active; not settable in dae syntax |
| `last_updated` | datetime? | null | Last fetch |
| `node_count` | u32 | `0` | Last count |
| `created_at` | datetime | now | Created |

Nodes are memory-only; periodic refresh merges via control plane.

---

## 7. Experimental (`experimental { ... }`)

```dae
experimental {
    clash_api {
        external_controller: '0.0.0.0:9090'
        external_ui: yacd
        secret: ''
        default_mode: Rule
    }
    cache_file {
        enabled: false
        path: 'cache.db'
        cache_id: ''
        store_fakeip: false
        store_dns: false
    }
}
```

### `experimental { clash_api { ... } }`

| Field | Default | Meaning |
| ------- | --------- | --------- |
| `external_controller` | `""` | Listen addr; empty = disabled |
| `external_ui` | `""` | Static UI dir |
| `secret` | `""` | Bearer / `?token=`; empty = no auth |
| `default_mode` | `"Rule"` | `Rule` / `Global` / `Direct` |

### HTTP API map (implemented)

| Method | Path | Purpose |
| -------- | ------ | --------- |
| GET | `/` `/version` | Hello / version |
| GET/PUT/PATCH | `/configs` | Mode and related |
| GET | `/proxies` | Nodes + groups |
| GET/PUT | `/proxies/{name}` | Detail / selector set |
| GET | `/proxies/{name}/delay` | On-demand delay |
| GET | `/group/{name}/delay` | Group delay |
| GET | `/rules` | Rules |
| GET/DELETE | `/connections` | List / close all |
| DELETE | `/connections/{id}` | Close one |
| GET | `/traffic` | WS or chunked JSON lines |
| GET | `/stats` | Outbound stats |
| GET | `/logs` | WS or chunked |
| GET | `/dns/query` | DoH-style JSON |
| POST | `/cache/fakeip/flush` | FakeIP prefix flush |
| POST | `/cache/dns/flush` | DNS cache flush |
| GET | `/providers/proxies` | Groups as providers |
| GET | `/providers/rules` | Stub empty |
| GET | `/ui` … | External UI |

Env: `HONK_UI_DOWNLOAD_URL` for UI zip override.

### `experimental { cache_file { ... } }`

| Field | Default | Meaning |
| ------- | --------- | --------- |
| `enabled` | `false` | Persist SQLite cache |
| `path` | `"cache.db"` | DB path |
| `cache_id` | `""` | Namespace id |
| `store_fakeip` | `false` | FakeIP persistence intent (engine incomplete) |
| `store_dns` | `false` | Persist DNS answers |

Stores selector choices and clash mode always when enabled.

---

## 8. CLI (`honk-core`)

| Flag | Default | Meaning |
| ------ | --------- | --------- |
| `-c` / `--config` | `/etc/honk/config.dae` | Config path |
| `-b` / `--bpf-object` | embedded | External eBPF object |
| `--bpf-pin-root` | `/sys/fs/bpf` | Pin root |
| `-d` / `--debug` | off | Debug logging |
| `--mock-ebpf` | off | No kernel eBPF |

Log level order: `--debug` → `RUST_LOG` → `global { log_level }` → `info`.

### Subcommands

```bash
honk-core mode <rule|global|direct>
honk-core proxy <group> <node>
honk-core delay <node> [--url HOST:PORT]
```

---

## 9. eBPF / runtime knobs (not all in config file)

| Item | Where | Notes |
| ------ | ------- | ------- |
| Embedded object | build `ebpf` feature | `build.rs` + `include_bytes!` |
| External object | `--bpf-object` | Override embed |
| Pin root | `--bpf-pin-root` | Default `/sys/fs/bpf` |
| Bypass mark | code `0x100` | Dial/probe/DNS upstream |
| tproxy mark | `global.tproxy_mark` | Policy / historical |
| Geo files | runtime path | `geoip.dat` / `geosite.dat` |
| UI download URL | `HONK_UI_DOWNLOAD_URL` | Clash external UI |

---

## 10. Health-check component behavior

Configured via `global { ... }` keys (`tcp_check_url`, `udp_check_dns`, `check_interval`, `check_tolerance`); per-group override fields exist in the internal schema but are not parsed from dae syntax. Implemented by `AliveDialerSet`:

| Behavior | Detail |
| ---------- | -------- |
| Domains | Tcp, DnsUdp, DataUdp × v4/v6 |
| TCP probe | HTTP method to `tcp_check_url` or raw connect |
| UDP probe | DNS to first usable `udp_check_dns` via node `dial_udp` |
| Concurrency | Default batch 10 |
| Recovery | 2 consecutive successes |
| New node grace | ~60s |
| URLTest idle | `idle_timeout` stops probes for unused groups |
| eBPF push | Dead outbounds excluded from redirect |

UDP selection exclusion: both UDP domains explicitly dead → not selected for UDP even if TCP is up; never-probed UDP inherits TCP liveness.

---

## 11. Related docs

- [Design](./design.en.md)
- [Configuration guide](./configuration.en.md)
- Examples: `config.dae`, `config.min.dae`
