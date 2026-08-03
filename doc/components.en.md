# honk Component Configuration Reference

Field-level reference for every major component. Companion to [configuration.en.md](./configuration.en.md).

honk is configured in the **dae configuration syntax** — sections like `include { ... }`, `global { ... }`, `node { ... }`, `group { ... }`, `routing { ... }`, `dns { ... }`, `subscription { ... }`, `experimental { ... }` with `key: value` pairs. `include` composes `.dae` files; see [configuration.en.md](./configuration.en.md#split-configuration-files) for its path and merge rules. See the root examples `config.dae` (full-featured) and `config.min.dae` (minimal).

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
| `tls_implementation` | `tls_implementation` | `"tls"` | TLS stack: `tls` (plain BoringSSL) / `utls` (real Chrome fingerprint) |
| `utls_imitate` | `utls_imitate` | `"chrome_auto"` | Fingerprint profile; `chrome*` maps to the built-in real Chrome profile (BoringSSL); any other value warns and falls back to Chrome (the only profile) |
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
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | Per-group UDP warm-up cap. `0` is strictly disabled: no coordinator task and no warm metrics. A positive value N (capped at 3) warms each group's top-N latency-ranked, UDP-capable leaves after startup and after every probe cycle (`check_interval`), so newly fast nodes are pre-dialed before they win a selection. Dispatch stays capped at four concurrent tasks. |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | Cap on concurrent proxied dials (connect + protocol handshake), scoped to the runtime generation. Built-in `direct`/`block` dials are exempt — they are local connects already bounded by the connection admission limit. A changed limit applies to new dials immediately on reload; in-flight dials keep their permits. |

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
| `encryption` | string? | null | SS/VMess cipher |
| `plugin` / `plugin_opts` | string? | null | Plugin name/opts |
| `transport` | string | `"tcp"` | `tcp` / `ws` / `grpc` / … (share-link `type=`/`net`) |
| `tls` | bool | `false` | Enable TLS |
| `sni` | string? | null | TLS SNI (share-link `sni=`) |
| `skip_cert_verify` | bool | `false` | Insecure TLS (share-link `allowInsecure=1`/`insecure=1`) |
| `ech_enabled` | bool | `false` | Offer ECH (share-link `ech=1`, or implied by `ech_config`) |
| `ech_config` | string? | null | Base64 ECHConfigList (share-link `ech_config=`) |
| `ech_config_path` | string? | null | File holding a base64 ECHConfigList |
| `network` | string? | null | V2Ray-style network hint |
| `ws_path` / `ws_host` | string? | null | WebSocket (share-link `path=`/`host=`) |
| `grpc_service` | string? | null | gRPC service name (`serviceName=`) |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 auth / salamander obfs password |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | null | Hysteria2 brutal bandwidth (`upmbps`/`downmbps`) |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | null | Hysteria2 port hopping (`mport`/`mhop`) |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | null | Hysteria2 QUIC receive windows |
| `hy2_disable_mtu_discovery` | bool? | null | Hysteria2 `disablePathMTUDiscovery` |
| `tls_pin_sha256` | string? | null | Leaf cert SHA-256 pin (`pinSHA256=`) |
| `tuic_uuid` / `tuic_password` / `tuic_congestion` | string? | null | TUIC |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | 8 MiB / quinn default | TUIC QUIC receive windows; the 8 MiB stream-window default lifts single-stream throughput on high-RTT links (quinn's 1.25 MiB caps ~12.5 MB/s per 100 ms RTT) |
| `juicity_uuid` / `juicity_password` | string? | null | Juicity |
| `anytls_password` | string? | null | AnyTLS secret |
| `anytls_min_idle_session` | usize? | 1 | Pool min idle sessions (`min_idle_session=`); default 1 keeps dials warm (0 = reap all idle sessions) |
| `anytls_idle_session_check_interval` | u64? | null | Idle check period, s (`idle_session_check_interval=`) |
| `anytls_idle_session_timeout` | u64? | null | Idle eviction, s (`idle_session_timeout=`) |
| `mark` | u32? | null | Outbound SO_MARK |
| `tags` | string[] | `[]` | Labels |
| `subscription_id` / `group_id` | UUID? | null | Ownership metadata |
| `created_at` / `updated_at` | datetime | now | Metadata |

\* Validation requires non-empty `name` and non-empty `address` or `host`.

### Protocols

| Value | Aliases | TCP | UDP | Notes |
| ------- | --------- | ----- | ----- | ------- |
| `ss` | `shadowsocks` | Yes | Yes | AEAD + `2022-blake3-*` |
| `trojan` | | Yes | Yes | TLS; WS/gRPC via transport |
| `vmess` | | Yes | No | AEAD; WS/gRPC |
| `vless` | | Yes | No | Header UDP exists in tests only |
| `socks5` | | Yes | Yes | UDP ASSOCIATE |
| `hysteria2` | | Yes | Yes | Real QUIC/H3; salamander; brutal (with bandwidth) or BBR; port hopping |
| `tuic` | | Yes | Yes | TUIC v5 / quinn |
| `juicity` | | Yes | Yes | quinn bi-stream UDP |
| `anytls` | | Yes | Yes | Session pool + UoT v2 |
| `direct` | | Yes | Yes | Built-in bypass outbound; reserved, injected at load (not configurable) |
| `block` | | — | — | Built-in reject outbound; reserved, injected at load (not configurable) |

Built-in **`direct`** and **`block`** nodes are injected at load (not required in config); user nodes may not take their names or protocols.

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

### TLS fingerprint and ECH

TLS runs on **BoringSSL** everywhere (proxy TLS, DoT/DoH upstreams, and QUIC handshakes via the custom quinn crypto backend). Two global modes:

- `tls_implementation: tls` — plain BoringSSL ClientHello.
- `tls_implementation: utls` — real Chrome fingerprint: GREASE, permuted extension order, X25519MLKEM768+X25519 key shares, Chrome sigalgs/curves, brotli certificate compression, ALPS for h2, and ECH GREASE. Applies to TCP TLS and QUIC ClientHellos alike.

Per-node **ECH** (Encrypted Client Hello) — works over TLS and over QUIC (hysteria2/juicity/tuic):

```dae
node {
    hy2_ech: 'hysteria2://secret@example.com:443?sni=example.com&ech_config=AD%2B-DQIAA...#hy2_ech'
}
```

- `ech_config=<base64 ECHConfigList>` (or `ech_config_path` in the JSON/TOML config forms) offers real ECH. Without configs, Chrome mode sends ECH GREASE like a real browser.
- ECH is fail-closed per RFC: if the server cannot accept ECH, the handshake fails (BoringSSL `ECH_REJECTED`) and any server-provided retry configs are logged.
- `ech_enabled` without a static config discovers the ECHConfigList from DNS HTTPS records (RFC 9460) at connect time — via the bootstrap resolver, or the first system nameserver when none is configured — cached per domain (record TTL for hits, 5 min for misses). Discovery is best-effort and fail-open: if no config is found, Chrome mode still sends ECH GREASE and the handshake proceeds without ECH.

**AnyTLS pool**

Pool tuning comes from share-link query parameters:

```dae
node {
    anytls1: 'anytls://secret@example.com:443?sni=example.com&min_idle_session=3&idle_session_check_interval=30s&idle_session_timeout=30s#anytls1'
}
```

**Hysteria2 / TUIC / Juicity**

Prefer share links; the `hy2_*` / `tuic_*` / `juicity_*` fields are derived from them. QUIC ALPN/congestion follow handler defaults (Hy2 uses BBR without bandwidth hints). For hysteria2 the userinfo carries the auth secret (→ `hy2_auth`), `obfs=salamander&obfs-password=<pwd>` maps to `hy2_obfs`, `upmbps`/`downmbps` enable the brutal sender and the `Hysteria-CC-RX` advertisement, `mport`/`mhop` enable client-side port hopping (the server must DNAT the range onto its listen port), `pinSHA256=<hex>` pins the leaf certificate fingerprint (replacing PKI/hostname checks), and `initStreamReceiveWindow`/`initConnReceiveWindow`/`disablePathMTUDiscovery` tune the QUIC transport:

```dae
node {
    hy2: 'hysteria2://secret@example.com:443?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfspw&upmbps=50&downmbps=200&mport=20000-30000&mhop=30#hy2'
}
```

### Share-link schemes

| Scheme | Notes |
| -------- | ------- |
| `ss://` | SIP002 |
| `vmess://` | base64 JSON (v2rayN) |
| `vless://` / `trojan://` | query params for transport/TLS |
| `anytls://` | pool params in query |
| `hysteria2://` / `tuic://` / `juicity://` | QUIC family |
| `socks5://` | simple |

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
| `check_url` | — | (global) | Per-group health check target (URLTest groups only, sing-box urltest `url`); dae: `check_url: 'http://...'` |
| — | `idle_timeout` | null | Stop checks after idle seconds; 0/None = never; not parsed in dae syntax |
| — | `interrupt_connections` | `false` | Drop flows on selection change; not parsed in dae syntax |
| — | `created_at` | now | Metadata |

### Policies

| Canonical | dae spellings | Behavior |
| ----------- | ------------- | ---------- |
| `selector` | `select`, `fixed`, `fixed(0)` | Manual pin; API + cache |
| `urltest` | `min_moving_avg`, `min_avg10`, `min_last_delay` | Lowest latency + tolerance; ranks by a halving moving average `(prev+sample)/2` (dae `min_moving_avg` semantics); **TCP/UDP separate** |
| `loadbalance` | `roundrobin`, `round_robin`, `balance` | Per-group, per-network RR among alive members |
| `fallback` | `fallback` | First alive sticky per TCP/UDP network; no instant failback |

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

Any matcher may be negated with a leading `!` (binds to the single matcher
that follows): `sip(10.10.10.24/32) && !dport(53) -> direct(must)`. A rule
matches iff every positive matcher matches and none of the negated ones do.
A flow with an unknown (unsniffed) domain is treated as "not x" for negated
domain/geosite matchers, so it never vetoes them.

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
| `not` | Negated matcher set (`!matcher(...)`), mirroring every field above |

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
        googledns: 'tcp+udp://dns.google:53' -> proxy
        google_doh: 'https://dns.google/dns-query' -> proxy
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
| `ipversion_prefer` | `strategy` | `both` when omitted; `preferipv4`/`preferipv6` when set to `4`/`6` | Address-family preference (`4`/`6`) |
| `optimistic_cache` | `cache.enabled` | `true` | Cache on/off |
| `optimistic_cache_ttl` | `cache.ttl` | `600` | Fixed positive-cache TTL (overrides answer min TTL; `0` keeps answer TTL) |
| `max_cache_size` | `cache.max_size` | `10000` | Max entries; `0` is accepted, warned, and clamped to `1` |

### Upstream

Each upstream is a `name: 'uri'` line; an optional trailing `-> tag` (or legacy `outbound: tag`) sends queries via a node/group.

| Field | Type | Default | Meaning |
| ------- | ------ | --------- | --------- |
| `name` | string | required | Id (the key before `:`) |
| `address` | string | required | `ip:port` or host (from the URI) |
| `protocol` | enum | `udp` | From URI scheme: `udp`/`tcp`/`tls`/`https`/`quic` (`tcp+udp`, `h3`/`http3` aliases) |
| `tls_server_name` | string? | null | DoT/DoH/DoQ/DoH3 SNI. dae syntax auto-derives from the hostname; for IP-literal upstreams set it explicitly as a URI query param, e.g. `tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com` |
| `outbound` | string? | null | Send via node/group (trailing `-> tag`) |

**Runtime note:** UDP/TCP/DoT/DoH/DoQ/DoH3 work with connection reuse. DoT/DoH/TCP support `-> proxy` (TCP tunnel via node/group). DoQ/DoH3 are direct-only for now. UDP+proxy is intentionally carried as TCP-DNS by this upstream policy; SOCKS5 RFC 1928 UDP remains a complete, independent transport.

### Routing / rules

| Item | Meaning |
| ------ | --------- |
| `request { <cond> [&& <cond>...] -> <action> }` | Request rules, first match wins. Conditions: `qname(suffix:/keyword:/full:/regex:/geosite:...)`, `qtype(a/aaaa/...)`; `!` negates a condition. Actions: `reject`, `asis` (dial the query's original destination), or an upstream name |
| `request { fallback: name }` | Upstream when no request rule matches |
| `response { <cond> [&& <cond>...] -> <action> }` | Response rules, first match wins. Conditions: `upstream(name)`, `qname(...)`, `ip(cidr, geoip:...)`; `!` negates. Actions: `accept`, `reject`, or an upstream name (re-query, depth ≤ 3) |
| `response { fallback: accept\|reject }` | Verdict when no response rule matches |
| `routing.rules[].domain` / `.upstream` | Legacy schema-only fields (`suffix:`/`keyword:`/`full:`/`regex:` prefixes), converted to request rules at load when no new-style rules exist |

### Strategy

Internal values: `preferipv4` | `preferipv6` | `ipv4only` | `ipv6only` | `both`.

- `ipv4only` / `ipv6only`: the other family's queries are answered NODATA at request time and never forwarded upstream.
- `preferipv4` / `preferipv6`: both families are forwarded. When the preferred family has answers for the name, the other family's response is suppressed (NODATA); when it has none, the other family's answers are returned (fallback allowed). The preferred-family check costs one extra upstream query per name on cache miss.
- `both`: the default `DnsConfig` strategy; eligible A and AAAA queries are forwarded concurrently and neither family is suppressed. A missing `ipversion_prefer` in honk's config keeps this default.

dae: `ipversion_prefer: 4` maps to `preferipv4`, `6` to `preferipv6` (anything else = `preferipv4`). The only-modes are not expressible in dae syntax.

### Cache

Persistence of DNS answers across restarts: `experimental { cache_file { store_dns: true } }`. Entries use the rollback-safe `dns:v2:` namespace and are restored only when their expiry, wire identity, ingress profile, scope, operation, and policy match. The v2 namespace starts cold and leaves legacy rows untouched. Older binaries ignore v2 rows, so a rollback can leave them in `cache.db` without changing behavior.

Cache and singleflight eligibility are intentionally shared. Only a standard
single-question QUERY with no answer/authority records and at most one
option-free EDNS-v0 OPT is eligible. RD/AD/CD, DO, exact question wire, UDP
size, ingress profile, policy, scope, and operation remain isolated in the
key. Unsupported flags, EDNS options (including ECS/COOKIE), EDNS-v1, and
multi-question messages bypass both optimizations; cancellation releases the
flight.

Runtime cache and singleflight keys share one immutable binary query identity;
operation variants retain that allocation, and cache sharding uses a precomputed
runtime hash. The SQLite text encoding remains confined to the persistence
boundary.


### Runtime and observability

Reload swaps one coherent generation containing DNS policy, Router,
GroupManager snapshot, transport manager, routing projection, and a pinned
outbound runtime. Leases let old requests keep their matching node/session
generation; after they and their DNS transports retire, old outbound pools
reject new opens and drain live streams. The retirement deadline and retained-
generation cap bound DNS shutdown, and transport initialization/close is
single-flight and idempotent.

Independent monotonic counters cover hit/miss/stale, flight
saturation/cancel/retry, persistence drop/flush failure, runtime retirement,
transport init/reset, projection failure/retry, and outcome classes. Recording
does not block on a shared gate. The internal best-effort scrape loads fields
separately and does not provide cross-counter coherence. Failure logs use
bounded `error_kind` values: forwarder
`engine`/`exchange`/`response`/`internal`/`rejected_plan`, persistence
`worker_closed`/`ack_dropped`/`worker_failed`/`database`, projection
`map_full`/`backend_write`, and transport `exchange_failed` with a bounded
transport label. They do not log query names, upstream addresses, or
free-form errors. `/stats` remains the outbound statistics surface; no public
DNS metric, endpoint, API, or tuning key is added.

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
| GET | `/stats` | Outbound and stable UDP stats |
| GET | `/logs` | WS or chunked |
| GET | `/dns/query` | DoH-style JSON |
| POST | `/cache/fakeip/flush` | FakeIP prefix flush |
| POST | `/cache/dns/flush` | DNS cache flush |
| GET | `/providers/proxies` | Groups as providers |
| GET | `/providers/rules` | Stub empty |
| GET | `/ui` … | External UI |

### `GET /stats` UDP schema

`udp` is a stable object nested in `GET /stats`. The dotted shorthand
`/stats.udp` below means that nested object, **not** a separate route. All listed
keys are always present; counters may be zero when their event has not occurred.
No dynamic node/tag labels are added on the packet path.

```text
udp = {
  endpoint: { hits, misses },
  latency: {
    route: H, dial: H, replyReady: H, firstSend: H, firstReply: H
  },
  capacity: { rejected },
  slowPermit: { accepted, rejected, closed },
  queue: { accepted, full, closed },
  firstSend: { failures },
  stagger: { attempts, winners, cancellations },
  warm: { attempts, successes, failures }
}
H = { count, sumNanos, buckets }  // buckets has 64 fixed log2 slots
```

`queue` is the endpoint-driver queue; it is distinct from `slowPermit`, which
records slow-path admission. Stagger counters are used only for cold URLTest
preparation. AnyTLS candidates use caller-owned provisional session slots counted
against the pool cap; loser cancellation closes detached work, while the winner
commits into the captured generation before endpoint publication. Warm `successes`
count only `Ready` or `AlreadyReady`; a `NotApplicable` result is neutral.

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
| UDP probe | DNS to first usable `udp_check_dns` via node `dial_udp_transport` |
| Per-group check URL | Groups with `check_url` probe members against it (sub-group members via their current pick, keyed by tag — sing-box RealTag); (tag, url) state independent of the global one — dead-for-this-URL excludes the member from that group only |
| Concurrency | Default batch 10 |
| Recovery | 2 consecutive successes |
| Deep backoff | After 10 consecutive failures, probing continues at the max-cooldown (300s) cadence — no permanent stop |
| Dial failure | Latency history cleared + one synthetic 10s penalty sample (sing-box `DeleteURLTestHistory` + flap guard); a node's pooled connections and UDP endpoints are purged when it flips alive→dead |
| UDP driver failure | Transport send/receive/reply-idle errors report a DataUdp traffic failure; intentional endpoint retirement and shutdown are health-neutral |
| Delay persistence | Last real delay sample per node saved to cache.db (60s writer), restored at startup, 24h age-out |
| New node grace | ~60s |
| URLTest idle | `idle_timeout` stops probes for unused groups |
| eBPF push | Dead outbounds excluded from redirect |

UDP selection exclusion: both UDP domains explicitly dead → not selected for UDP even if TCP is up; never-probed UDP inherits TCP liveness.

---

## 11. Related docs

- [Design](./design.en.md)
- [Configuration guide](./configuration.en.md)
- [DNS canary and rollback runbook](./dns-rollout.en.md)
- Examples: `config.dae`, `config.min.dae`
