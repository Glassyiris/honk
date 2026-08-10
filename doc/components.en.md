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
| `lan_interface` | `lan_interface` | `[]` | LAN ifaces to intercept (comma-separated); empty installs no LAN hooks |
| `wan_interface` | `wan_interface` | `[]` | WAN ifaces that intercept host-originated TCP/UDP. `auto` follows the IPv4 default route; while none exists it stays pending (never falls back to `lo`) and attaches on link/address/route events. The same event republishes generated gateway-address `direct(must)` rules and immediately re-probes health-backed outbounds. |
| `auto_config_kernel_parameter` | `auto_config_kernel_parameter` | `false` | Auto sysctl (root) |
| `data_dir` | `data_dir` | `"/var/share/honk"` | Non-empty absolute root for generated state and relative runtime assets. Changing it requires a process restart. |
| `store_subscribe` | `store_subscribe` | `true` | Persist each last valid subscription body in `.sub` below `global.data_dir` for network-independent startup/reload recovery. An existing `./.sub` store is retained until moved. Changing it requires a process restart. |
| `tcp_check_url` | `tcp_check_url` | gstatic HTTPS | TCP health target. HTTPS performs verified target TLS before the configured HTTP method. |
| `tcp_check_http_method` | `tcp_check_http_method` | `"HEAD"` | HTTP method for URL checks |
| `udp_check_dns` | `udp_check_dns` | dns.google / 8.8.8.8 / IPv6 | UDP health DNS targets (comma-separated) |
| `check_interval` | `check_interval_secs` | `30` | Health interval, duration form (e.g. `30s`) |
| `check_tolerance` | `check_tolerance_ms` | `50` | URLTest switch delta, duration form (e.g. `50ms`) |
| `dial_mode` | `dial_mode` | `"domain"` | `ip` / `domain` / `domain+` / `domain++` |
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
| `preconnect_node_count` | `preconnect_node_count` | `'auto'` | One startup bare-TCP preconnect pass. `'auto'` tries up to 8 nodes; `0` disables; explicit `N` can cover every eligible node with at most 8 concurrent attempts. Candidates are each group's current pick first, then config order; only bare-TCP-poolable protocols qualify (AnyTLS/QUIC and built-in `direct`/`block` are skipped). |
| `udp_warm_node_count` | `udp_warm_node_count` | `0` | Per-group UDP warm-up cap. `0` is strictly disabled. A positive N takes each group's top `min(N,3)` latency-ranked UDP leaves; its independent coordinator runs immediately, then one `check_interval` after each completed batch, with at most four concurrent attempts. The process-wide retained set is re-ranked and capped at `4×N`. |
| `max_concurrent_dials` | `max_concurrent_dials` | `64` | Generation-local cap on physical proxied connects and protocol handshakes, clamped to an immutable process-wide startup descriptor gate shared by overlapping reload generations. Ready-pool hits and logical streams on already-warm AnyTLS/QUIC transports bypass it; built-in `direct`/`block` dials are also exempt. A changed limit applies to the replacement generation immediately; old-generation in-flight permits continue consuming the same process gate until they finish. |

```dae
global {
    tproxy_port: 12345
    log_level: info
    data_dir: '/var/share/honk'
    lan_interface: podman0
    wan_interface: auto
    dial_mode: domain++
    allow_insecure: false
    auto_config_kernel_parameter: true
    tcp_check_url: 'https://www.gstatic.com/generate_204'
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
| `id` | UUID | content-derived | Stable identity: UUID v5 over `protocol\|host\|port\|credential\|dial-shape` (dial shape = sni/transport/ws/grpc/obfs plus the REALITY/flow handshake shape); renames keep it, two nodes deriving the same ID are rejected (subscription duplicates are skipped with a warning) |
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
| `ech_config_path` | string? | null | File holding a base64 ECHConfigList. A relative path prefers `<global.data_dir>/<path>` and falls back to the legacy working-directory-relative file. |
| `reality_public_key` | string? | null | REALITY server X25519 public key (share-link `pbk`); when set the node takes the REALITY handshake instead of plain TLS (`security=reality` implies `tls=true`) |
| `reality_short_id` | string? | null | REALITY short id (share-link `sid`, even-length hex ≤ 8 bytes) |
| `reality_spider_x` | string? | null | REALITY spider path (share-link `spx`, share-link default `/`) |
| `flow` | string? | null | VLESS flow control (share-link `flow=`); only `xtls-rprx-vision` is supported and it requires TLS or REALITY — enforced by `Config::validate` |
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
| `anytls_min_idle_session` | usize? | null (effective 0) | Explicit pool standby floor (`min_idle_session=`). A selected Selector leaf independently raises its effective floor to at least one; `0` otherwise lets idle sessions drain. |
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
| `vmess` | | Yes | No | AEAD; WS/gRPC; REALITY via `security=reality`; registered only with the `rprx` feature (on in honk-core's default build) |
| `vless` | | Yes | No | REALITY + `xtls-rprx-vision` flow; WS/gRPC via transport; registered only with the `rprx` feature |
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

Verified VLESS combinations (live interop against a sing-box 1.13 server): TCP+REALITY+vision, TCP+REALITY, TCP+WS, TCP+WS+TLS, TCP+gRPC. The `xtls-rprx-vision` flow only combines with TCP+REALITY/TLS — over WS/gRPC there is no raw socket for the XTLS direct-copy switch, matching upstream.

Clash subscriptions map VLESS `uuid`, `servername`/`sni`, `flow`, `network`,
nested `reality-opts`, `ws-opts`, and `grpc-opts` into the same node fields
before identity derivation. Incomplete `reality-opts` entries are skipped.
Feed shapes outside TCP/WS/gRPC, non-Vision flows, Vision without TLS/REALITY,
and Vision over WS/gRPC are reported by `honk-tool sub` but not probed.
`client-fingerprint` is not a node field; the global TLS mode owns it.

**VLESS + REALITY (xtls-rprx-vision)**

`security=reality` switches a vless (or vmess) node from plain TLS to the REALITY handshake; `pbk`/`sid`/`spx` carry the REALITY parameters and `flow=xtls-rprx-vision` enables the XTLS Vision splice:

```dae
node {
    vless_r: 'vless://uuid@example.com:443?security=reality&sni=dl.google.com&pbk=<base64url-pubkey>&sid=ab12&flow=xtls-rprx-vision#vless_r'
}
```

- An explicit `security=` overrides the historical vless TLS-on default: `security=none` disables TLS, any other value enables it; a link without `security=` parses exactly as before (vless TLS on, vmess off). `fp=` is accepted but ignored — the ClientHello fingerprint follows the global `tls_implementation` mode.
- REALITY needs no CA and no `skip_cert_verify`: the server is authenticated post-handshake against the REALITY auth key (see `doc/design.en.md`), and authentication failure is fail-closed.
- Pick a REALITY `dest`/SNI whose TLS Certificate message stays under 8 KiB (sing-box reality buffers 8192 bytes) — `dl.google.com` works, `www.microsoft.com` does not.
- VMess and VLESS handlers are compiled behind honk-outbound's `rprx` cargo feature (enabled by default in honk-core). A build without it parses such nodes but refuses dials with "No handler for protocol".

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
| `vless://` / `trojan://` | query params for transport/TLS; vless/vmess also take `security=reality|tls|none`, `pbk`, `sid`, `spx`, `flow` (REALITY + xtls-rprx-vision) |
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
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | Subscription provenance filter; exact/`keyword:`/`regex:` tag matching |
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
| `selector` | `select`, `fixed`, `fixed(0)` | Manual pin; API + cache. Its configured leaf is always warm: reusable AnyTLS/QUIC state or one bare server TCP for other proxy protocols. |
| `urltest` | `min_moving_avg`, `min_avg10`, `min_last_delay` | Lowest latency + tolerance; ranks by a halving moving average `(prev+sample)/2` (dae `min_moving_avg` semantics); **TCP/UDP separate** |
| `loadbalance` | `roundrobin`, `round_robin`, `balance` | Per-group, per-network RR among alive members |
| `fallback` | `fallback` | First alive sticky per TCP/UDP network; no instant failback |

### Filter resolution

1. `filter: group('tag')` → nested tags (`groups`), not node list.
2. `name(...)` matches node names; `subtag(...)` matches the tag of the subscription that produced a node. Both accept exact, `keyword:`, and `regex:` arguments and are case-sensitive.
3. Predicates joined with `&&` on one line are AND-ed and support `!` negation; separate `filter:` lines are OR-ed.
4. Filter-derived node membership is rebuilt after subscription refresh, so stable node IDs cannot retain membership after moving between subscriptions.
5. No filters and no nested groups → **all nodes**; nested groups only → **not** all nodes.

### Nested groups

Depth capped at 8; cycles cut at construction with a warning. Dial always resolves to one **leaf** node. Clash `all` shows member tags; health checks expand leaves.

---

## 4. Routing (`routing { ... }`)

Rules are condition functions joined with `&&`, followed by `-> outbound` (optionally `outbound(must)`), in match order, ending with a `fallback:`. Parenthesized matcher arguments may span physical lines without splitting the rule:

```dae
routing {
    pname(NetworkManager, systemd-resolved) && l4proto(udp) && dport(53) -> direct(must)
    domain(suffix: example.com, geosite: cn) -> proxy
    domain(keyword: m-team) -> direct
    dip(geoip: cn) -> direct(must)
    sip(10.10.10.24/32,
        10.10.10.25/32
    ) -> direct
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
| `outbound` | string | required | One node/group tag (the `->` right-hand side in dae syntax) |
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

`domain` arg tags: bare/`suffix:` → suffix; `keyword:`; `full:`; `regex:`; `geosite:` (verbatim; `category@attr` filters entries by attribute key, dae semantics — case-insensitive, everything after the first `@` is the selector; zero-match expansion warns and never matches). `dip` args: plain CIDRs or `geoip: code`.

---

## 5. DNS (`dns { ... }`)

```dae
dns {
    # bind: 'tcp+udp://:1053'   # leave commented to keep standalone DNS off
    ipversion_prefer: 4
    use_host: true
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
| `bind` | `bind` | `""` | Optional standalone UDP/TCP listener in the host network namespace; empty disables only this listener |
| `use_host` | `use_host` | `false` | Resolve IN-class A/AAAA queries from `/etc/hosts` before DNS routing, cache, and upstreams |
| `upstream { ... }` | `upstream` | one `default` @ 223.5.5.5 UDP | Servers |
| `routing { ... }` | `routing` | fallback default | Request routing |
| `ipversion_prefer` | `strategy` | `both` when omitted; `preferipv4`/`preferipv6` when set to `4`/`6` | Address-family preference (`4`/`6`) |
| `optimistic_cache` | `cache.enabled` | `true` | Cache on/off |
| `optimistic_cache_ttl` | `cache.ttl` | `600` | Fixed positive-cache TTL (overrides answer min TTL; `0` keeps answer TTL) |
| `max_cache_size` | `cache.max_size` | `10000` | Max entries; also scales the retained query/response wire-byte budget at 4 KiB/entry (minimum 65,535 bytes/shard, global maximum 64 MiB); `0` is accepted, warned, and clamped to `1` |

### Hosts file

With `use_host: true`, generation construction reads `/etc/hosts` once. Each
valid address line contributes its canonical name and aliases; matching is
exact and ASCII case-insensitive, trailing dots are normalized, duplicate
addresses are removed, and both IPv4 and IPv6 are supported. Invalid-address
lines and comments are ignored.

Hard `ipv4_only`/`ipv6_only` strategy filtering remains first. Otherwise a
known IN-class A/AAAA name takes precedence over request rules (including
`reject`), cache entries, and upstreams. If the name exists but has no address
in the requested family, honk returns NOERROR/NODATA instead of leaking the
query upstream. Non-address qtypes and non-IN classes keep the normal routing
path. Host answers participate in the normal DNS routing projection, advertise
a 60-second TTL, and bypass honk's response cache.

The loaded table is immutable for the lifetime of its DNS runtime generation;
the query path never reads the file. Send SIGHUP after editing `/etc/hosts`.
The replacement generation loads the new snapshot atomically while in-flight
leases may finish on the old one. If the file cannot be read, startup fails or
the reload aborts before publication, retaining the active generation.

### Standalone listener

`dns.bind` accepts exactly these dae-compatible forms:

| Value | Listener |
| ----- | -------- |
| absent or `""` | Disabled; transparent TCP/UDP port-53 interception remains active |
| numeric `IP:port`, for example `127.0.0.1:1053` or `[::1]:1053` | UDP only |
| `udp://host:port` | UDP |
| `tcp://host:port` | TCP |
| `tcp+udp://host:port` | TCP and UDP |

Schemed forms accept a hostname (`udp://localhost:1053`), a bracketed IPv6
literal (`tcp://[::1]:1053`), or an empty host as a wildcard
(`tcp+udp://:1053`). The port is always explicit; `0` requests an ephemeral
port and the selected address is logged. A bare hostname is invalid, and
userinfo, paths, queries, fragments, and IPv6 zone identifiers are rejected.
Hostnames select the first resolved address on which every requested transport
can bind.

These are ordinary, unmarked host-netns sockets. A LAN-facing local TCP or UDP
listener on `:53` takes precedence for its transport; wildcard precedence is
limited to host-local destinations. Disabling `bind` does not disable
transparent port-53 interception. All requested sockets are bound
synchronously and all-or-nothing: one bind failure closes the others and fails
startup. The listener is process-owned, so a semantic endpoint change on
SIGHUP is rejected as restart-required; an unchanged endpoint continues using
the newly published DNS runtime. Wildcard and LAN binds expose an unauthenticated
recursive resolver and require host-firewall source restrictions.

Each query uses the current `DnsServiceProvider` generation and therefore the
same request/response routing, cache, singleflight, upstream pools, and routing
projection as transparent DNS. Only complete single-question requests are
forwarded. UDP reply limits clamp the client EDNS size to `512..=1232` and
preserve the queried local address on wildcard sockets. TCP DNS on both transparent and standalone paths uses persistent RFC 7766
two-octet framing and bounds every length/body read and response write to 30
seconds. Standalone TCP consumes at most one quarter of the global connection
budget.
Standalone queries have no intercepted original destination: if request
routing selects `asis`, honk returns a DNS failure rather than recursing into
its own listener.

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
| `request { <cond> [&& <cond>...] -> <action> }` | Request rules, first match wins. Conditions: `qname(suffix:/keyword:/full:/regex:/geosite:...)`, `qtype(a/aaaa/...)`; `!` negates a condition. Actions: `reject`, `asis` (transparent queries preserve the client transport when dialing the intercepted destination, with UDP TC→TCP retry; standalone queries return a DNS failure), or an upstream name |
| `request { fallback: name }` | Upstream when no request rule matches |
| `response { <cond> [&& <cond>...] -> <action> }` | Response rules, first match wins. Conditions: `upstream(name)`, `qname(...)`, `ip(cidr, geoip:...)`; `!` negates. Actions: `accept`, `reject`, or an upstream name (re-query, depth ≤ 3) |
| `response { fallback: accept\|reject }` | Verdict when no response rule matches |
| `routing.rules[].domain` / `.upstream` | Legacy schema-only fields (`suffix:`/`keyword:`/`full:`/`regex:` prefixes), converted to request rules at load when no new-style rules exist |

### Strategy

Internal values: `preferipv4` | `preferipv6` | `ipv4only` | `ipv6only` | `both`.

- `ipv4only` / `ipv6only`: the other family's queries are answered NODATA at request time and never forwarded upstream.
- `preferipv4` / `preferipv6`: both families are forwarded. When the preferred family has answers for the name, the other family's response is suppressed (NODATA); when it has none, the other family's answers are returned (fallback allowed). The preferred-family check costs one extra upstream query per name on cache miss and preserves the original query wire profile except for QTYPE.
- `both`: the default `DnsConfig` strategy; eligible A and AAAA queries are forwarded concurrently and neither family is suppressed. A missing `ipversion_prefer` in honk's config keeps this default.

dae: `ipversion_prefer: 4` maps to `preferipv4`, `6` to `preferipv6` (anything else = `preferipv4`). The only-modes are not expressible in dae syntax.

### Cache

Persistence of DNS answers across restarts: `experimental { cache_file { store_dns: true } }`. Entries use the rollback-safe `dns:v2:` namespace and are restored only when their expiry, wire identity, ingress profile, scope, operation, and policy match. The v2 namespace starts cold and leaves legacy rows untouched. Older binaries ignore v2 rows, so a rollback can leave them in `cache.db` without changing behavior.

Cache and singleflight eligibility are intentionally shared. Only a standard
single-question QUERY with no answer/authority records and at most one
option-free EDNS-v0 OPT is eligible. RD/AD/CD, DO, exact question wire, UDP
size, ingress profile, policy, scope, and operation remain isolated in the
key. Multi-question requests are rejected before policy planning. Unsupported
flags, EDNS options (including ECS/COOKIE), and EDNS-v1 bypass both
optimizations; cancellation releases the flight.

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
free-form errors. `/stats` remains the outbound statistics surface; runtime
DNS telemetry adds no public metric or API.

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

Nodes remain runtime-only and are never written into the config file. With
`global { store_subscribe: true }` (the default), each successfully fetched and
parsed raw body is atomically stored in `.sub` below `global.data_dir`; an
existing legacy `./.sub` store is retained until moved. The directory is mode `0700`,
files are mode `0600`, and filenames are hashes of the URL plus request identity.
Startup restores valid bodies before network refresh. A restored subscription does not consume the five-second
grace period, but its online refresh still runs in the background. Reload
first carries active nodes and uses the stored body for any enabled subscription
without carried nodes. Fetch, parse, or store failure keeps both the active
nodes and the last valid stored body.

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
    udp_nfqueue {
        enabled: false
    }
}
```

### `experimental { udp_nfqueue { ... } }`

| Field | Default | Meaning |
| ------- | --------- | --------- |
| `enabled` | `false` | Hold ambiguous LAN-forwarded UDP first packets in NFQUEUE for a final userspace decision |

This field is restart-required. When it is `true`, startup accepts only a build
with the `ebpf` feature using the real eBPF backend; `--mock-ebpf` and builds
without `ebpf` are rejected. The hook covers LAN-forwarded traffic because host
`inet prerouting` follows LAN TC. Host-originated WAN egress stays on the
canonical TPROXY path. DNS port 53, internal/special traffic, `must`, `block`,
reverse traffic, and already-safe direct decisions are never queued; only
ambiguous userspace/domain decisions are staged.

The mechanism is fixed: raw-netlink queue `320`, one listener, and no bypass,
fanout, fail-open, or user-selectable queue/worker policy. honk exclusively owns
the exact nftables names `inet honk_nfqueue` / `udp_decision`; firewall managers
in the same network namespace must not mutate them while honk runs. The pinned
`UDP_DECISION_SEQUENCE` allocator survives ordinary restart/cleanup and cannot
be reset without risking token reuse; exhaustion requires a reboot.

Held skbs are before conntrack/NAT. A final direct decision uses a token-checked
Arm → FIFO accept with the final mark → Activate transition and creates no
userspace direct socket, payload copy, deliberate retransmission, endpoint, or
connection entry. Proxy first commits its token-bound state, moves the one
retained payload copy into the canonical UDP initializer, drops the originals,
then dials/sends exactly once. Block/cancel drop. Reload and shutdown fence
readiness and quiesce/cancel all guards before queue/table teardown.
Queue/listener/verdict failures and token exhaustion are fatal.

### `experimental { clash_api { ... } }`

| Field | Default | Meaning |
| ------- | --------- | --------- |
| `external_controller` | `""` | Listen addr; empty = disabled |
| `external_ui` | `""` | Static UI dir; relative paths prefer an existing directory below `global.data_dir`, then an existing working-directory-relative directory; missing paths target `global.data_dir` |
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
| GET | `/rules` | One row per rule: native Clash type for simple matchers; `complex` + full statement for compound, negated, or `must` dae rules |
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
  warm: { attempts, successes, failures },
  nfqueue: {
    received, activeFlows, directAccepted, proxyCopied, proxyDropped,
    block, cancel, drop, tokenMismatch, tokenExhaustion, verdictErrors,
    receiptToVerdict: H
  }
}
H = { count, sumNanos, buckets }  // buckets has 64 fixed log2 slots
```

`queue` is the endpoint-driver queue; it is distinct from `slowPermit`, which
records slow-path admission. Stagger counters are used only for cold URLTest
preparation. AnyTLS candidates use caller-owned provisional session slots counted
against the pool cap. QUIC candidates use detached clients. Loser cancellation closes
either form of detached work; the winner finishes promotion/arbitration before endpoint
publication. If ordinary traffic already filled a QUIC generation slot, that incumbent
remains and the winning transport owns its connection only for the selected flow. Warm
`successes` count `Ready`; a `NotApplicable` result is neutral.

`nfqueue.received` counts listener deliveries and `activeFlows` is the current
pending-correlator gauge. `directAccepted`, `proxyDropped`, `block`, `cancel`,
and `drop` count successful kernel verdicts; `proxyCopied` counts the single
payload ownership transfer into the canonical initializer. `tokenMismatch`,
`tokenExhaustion`, and `verdictErrors` expose fail-closed faults.
`receiptToVerdict` measures listener receipt to successful verdict and is not
labelled as kernel queue residence because NFQA timestamps are not guaranteed.

`/stats` also carries a top-level `warm` object of point-in-time gauges:

```text
warm = {
  nodes: { preconnect, health, udp, selector, traffic },
  sessions: { anytls, tuic, juicity, hysteria2 }
}
```

`nodes` counts currently warm nodes by the reason retaining their resources
(a node may count under several reasons; a warm node with no recorded reason
counts as `traffic`). `selector` is the always-on pin for configured Selector
leaves. `sessions` counts retained AnyTLS pool sessions and occupied QUIC
client slots per protocol. Gauges track the live generation: a node whose
resources drain drops out of the next snapshot.

Env: `HONK_UI_DOWNLOAD_URL` for UI zip override.

### `experimental { cache_file { ... } }`

| Field | Default | Meaning |
| ------- | --------- | --------- |
| `enabled` | `false` | Persist SQLite cache |
| `path` | `"cache.db"` | DB path; relative paths prefer `global.data_dir`, then an existing path relative to the original config directory |
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
| Recovery | 2 consecutive successes; a relevant link/address/route change clears stale cooldown and lets the next successful probe verify recovery |
| Dead-node retry | Due dead TCP/UDP families are reconsidered every `min(5s, check_interval)`; actual probes still honor the 5s→300s exponential backoff |
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
