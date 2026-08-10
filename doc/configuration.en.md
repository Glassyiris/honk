# honk Configuration Guide

This guide covers how to configure **honk**: the configuration format, top-level sections, and common examples.

For field-by-field component details (every node/group/DNS/CLI option), see [components.en.md](./components.en.md).

## 1. Configuration format

honk is configured in the **dae configuration syntax** — the original `{ section { ... } }` language used by [dae](https://github.com/daeuniverse/dae):

- Configuration is organized into **sections**: `include { ... }`, `global { ... }`, `node { ... }`, `group { ... }`, `routing { ... }`, `dns { ... }`, `subscription { ... }`, `experimental { ... }`.
- Inside non-`include` sections, settings are `key: value` pairs, one per line.
- Strings containing special characters (URLs, `+`, `//`, `:`) should be **quoted** (single or double quotes both work): `tcp_check_url: 'https://www.gstatic.com/generate_204'`.
- Lists are comma-separated inside a single value: `lan_interface: eth0, eth1`.
- Durations accept suffixes: `30s`, `50ms`, `5m`, `1h`.
- `#` starts a comment (whole-line or trailing).

Repo examples:

- `config.dae` — full-featured example
- `config.min.dae` — minimal example (good for dev / `--mock-ebpf`)

### Split configuration files

Use a top-level `include` section to compose a configuration from `.dae` files:

```dae
include {
    config.d/*.dae
    '/etc/honk/config.d/extra config.dae'
}
```

- Entries may be bare or quoted and support `*`, `?`, and `[]` glob patterns. Matches are loaded in lexical order; unmatched patterns, directories, and non-`.dae` files are skipped.
- Relative paths are resolved from the directory of the entry config passed to `--config`, even in nested includes. Absolute paths are accepted only when they remain under that entry directory; symlink targets are checked as well.
- The entry file's sections are merged first, followed by each included file and its descendants. Later scalar settings override earlier ones; nodes, groups, upstreams, and routing rules append in that order.
- Repeating a file (including through a cycle) is rejected.


### Runtime data directory

`global.data_dir` selects the runtime-state root independently of the process
`WorkingDirectory`. It must be a non-empty absolute path and defaults to
`/var/share/honk`; changing it requires a process restart. New relative
`experimental.cache_file.path` and `experimental.clash_api.external_ui` values
target it, as does the durable `.sub` subscription store. Parent directories
are created as needed. Absolute child paths remain literal. For upgrade
compatibility, an existing cache relative to the original config directory, an
existing `./.sub` store, or an existing working-directory-relative UI directory
remains in use until moved below the configured data directory.

Place runtime-supplied `geoip.dat`, `geosite.dat`, and a relative
`ech_config_path` below `global.data_dir` to make systemd and manual starts
behave identically. An explicit `$DAE_LOCATION_ASSET` geo directory takes
precedence; otherwise geo assets fall back to the working directory and dae's
standard asset directories. For compatibility, a relative `ech_config_path`
falls back to its old working-directory-relative location when no data-directory
copy exists.
## 2. Top-level structure

```text
include { ... }        # merge additional .dae configuration files
global { ... }         # transparent proxy, health checks, dial mode, timeouts
node { ... }           # static proxy nodes (share links)
group { ... }          # selection policies over nodes / nested groups
routing { ... }        # ordered traffic rules + fallback outbound
dns { ... }            # upstreams, DNS routing, cache
subscription { ... }   # remote node lists
experimental { ... }   # clash_api, cache_file, udp_nfqueue
```

Built-ins:

- Outbounds **`direct`** and **`block`** are auto-injected at load as reserved protocol nodes (usable in groups/filters/routing); user nodes may not take their names or protocols.
- **`block`** drops traffic.

## 3. Minimal configuration

```dae
global {
    wan_interface: auto
    lan_interface: eth0
    log_level: info
    dial_mode: domain
    auto_config_kernel_parameter: true
    tcp_check_url: 'https://www.gstatic.com/generate_204'
    check_interval: 30s
    check_tolerance: 50ms
    bootstrap_resolver: '223.5.5.5:53'
}

node {
    trojan-node: 'trojan://password@trojan.example.com:443?sni=trojan.example.com'
}

group {
    proxy {
        filter: name(keyword: 'node')
        policy: min_moving_avg
    }
}

routing {
    dip(geoip: private) -> direct
    domain(suffix: google.com, suffix: youtube.com) -> proxy
    fallback: direct
}

dns {
    ipversion_prefer: 4
    upstream {
        alidns: 'udp://223.5.5.5:53'
    }
    routing {
        request {
            fallback: alidns
        }
    }
}
```

## 4. A fuller example

```dae
global {
    tproxy_port: 12345
    log_level: info
    lan_interface: eth0
    wan_interface: auto
    auto_config_kernel_parameter: true
    tcp_check_url: 'https://www.gstatic.com/generate_204'
    check_interval: 30s
    dial_mode: domain
    bootstrap_resolver: '223.5.5.5:53'
}

node {
    trojan-node: 'trojan://trojan-password@trojan.example.com:443?sni=trojan.example.com'
}

group {
    proxy {
        filter: name(keyword: 'node')
        policy: min_moving_avg
    }
}

routing {
    dip(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) -> direct
    domain(suffix: google.com, suffix: youtube.com, suffix: github.com) -> proxy
    fallback: direct
}

dns {
    upstream {
        alidns: 'udp://223.5.5.5:53'
    }
    routing {
        request {
            fallback: alidns
        }
    }
    optimistic_cache: true
    # Fixed positive-cache TTL (overrides answer min TTL for cache + wire RR TTLs).
    # Set 0 to keep the upstream answer TTL instead.
    optimistic_cache_ttl: 600
    max_cache_size: 10000
}

experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        secret: 'change-me'
        default_mode: 'Rule'
    }
    cache_file {
        enabled: true
        path: 'cache.db'
        store_dns: true
    }
    udp_nfqueue {
        enabled: false
    }
}
```

## 5. Global essentials

All of these live in the `global { ... }` section:

| Topic | Key fields | Guidance |
| ------- | ------------ | ---------- |
| Intercept | `lan_interface`, `wan_interface` | Omit LAN to install no LAN hooks; configured WAN hooks still proxy host-originated TCP/UDP. `auto` follows the IPv4 default-route iface, stays pending when no route exists, and attaches after link/address/route changes without a restart; generated gateway-address `direct(must)` rules are republished and health-backed outbounds are re-probed at the same time. |
| Listen | `tproxy_port` | Default `12345`; the TPROXY traffic mark defaults to `0x08000000`. |
| Kernel | `auto_config_kernel_parameter` | Needs root; enables helpful sysctls |
| Health | `tcp_check_url`, `udp_check_dns`, `check_interval`, `check_tolerance` | Drives AliveDialerSet / URLTest. Durations: `check_interval: 30s`, `check_tolerance: 50ms`. |
| Dial | `dial_mode` | `ip` / `domain` / `domain+` / `domain++` |
| Resolve | `bootstrap_resolver`, `fallback_resolver` | Avoid self-intercept when resolving node hostnames |


**WAN-only host proxy:** omit `lan_interface` when the machine has no downstream LAN traffic to intercept:

```dae
global {
    wan_interface: ens3
    dial_mode: ip
}
```

This installs only the WAN ingress/egress hooks. TCP and UDP created by the host and leaving `ens3` are routed through honk; forwarded LAN and loopback traffic are untouched. Do not add `lo` as a synthetic LAN interface.

**Dial modes:**

| Value | When to use |
| ------- | ------------- |
| `ip` | Simple IP routing; no sniff |
| `domain` | Default; sniff + verify against dest IP |
| `domain+` | DNS does not go through honk |
| `domain++` | Force sniff and re-route on SNI/Host |

### Warm-up and dial budget

honk has three independent warm-up mechanisms. Their bounds depend on
configured groups or explicit budgets rather than raw subscription size:

| Mechanism | Key | Default | Notes |
| ----------- | ----- | --------- | ------- |
| Bare TCP preconnect at startup | `preconnect_node_count` | `'auto'` | One startup pass only. `'auto'` tries up to 8 nodes (each group's current pick first, then config order); `0` disables; explicit `N` may cover all eligible nodes with at most 8 concurrent attempts. Only bare-TCP-poolable protocols qualify — AnyTLS/QUIC and the built-in `direct`/`block` are always skipped. |
| Selector pin | — | always on | Keeps the configured leaf of every `selector` group warm, including an explicitly selected node while it is unhealthy. AnyTLS and QUIC protocols retain their reusable session/client; other proxy protocols retain one bare server TCP connection. A Clash API choice change wakes reconciliation immediately, releases the previous leaf without cutting active flows, and warms the replacement. Reload preserves ownership for unchanged selected nodes. |
| UDP warm set | `udp_warm_node_count` | `0` | Takes the top `min(N,3)` UDP leaves per group and IP family, dispatches at most 4 attempts concurrently, and caps the process-wide retained set at `4×N`. UDP and Selector ownership are independent: a shared resource is released only after both reasons disappear. |
| Concurrent dial cap | `max_concurrent_dials` | `64` | Bounds physical proxy connects and protocol handshakes per generation. Ready-pool hits, logical streams on warm AnyTLS/QUIC transports, and built-in `direct`/`block` dials are exempt. Reload changes the replacement's local limit, while old and new generations share one immutable startup descriptor gate. |

Health checks probe but never warm a cold node, so `check_interval` on a
400-node subscription does not create 400 idle tunnels. The Selector pin is
reconciled every 10 seconds as a repair backstop. `/stats` exposes the live
warm inventory under `warm` (reason × hot-node count, sessions per protocol).

## 6. Nodes and share links

Nodes are declared as **share links** inside the `node { ... }` section, either with an explicit tag or bare. Single- and double-quoted forms are both accepted; an entry that fails to parse is skipped with a warning on stderr:

```dae
node {
    my-trojan: 'trojan://password@trojan.example.com:443?sni=trojan.example.com'
    'socks5://user:pass@10.0.0.1:1080'
}
```

Supported schemes (parser): `ss://`, `socks5://`, `trojan://`, `vmess://`, `vless://`, `hysteria2://`, `tuic://`, `juicity://`, `anytls://`.

Node parameters (credentials, `sni`, transport/ws/grpc options, protocol-specific Hy2/TUIC/Juicity/AnyTLS options) are carried by the share link's userinfo/host/query components — the same fields the `Node` model exposes (`name`, `protocol`, `address`/`host`, `port`, `password`/`username`, `encryption`, `tls`, `sni`, `transport`, `ws_path`, `ws_host`, `grpc_service`, ...). An explicit `tag:` prefix overrides the name embedded in the link.

See [components.en.md](./components.en.md) for the full field table and protocol notes (including UDP support matrix).

## 7. Groups

Groups are named sub-sections of `group { ... }`:

```dae
group {
    proxy {
        filter: subtag('my-sub') && !name(keyword: 'ExpireAt-')
        filter: name('us1')              # another filter line is OR-ed
        filter: group('hk', 'jp')        # nested sub-groups (optional)
        policy: min_moving_avg      # selector | urltest | loadbalance | fallback (aliases below)
        default: 'us1'              # selector default
        final: direct               # when all members are dead
    }
}
```

Group-level knobs without a dae-syntax key keep their defaults: URLTest `tolerance` (hysteresis) defaults to 50 ms, `idle_timeout` to never stop, and `interrupt_connections` to false.

**Filters:**

| Expression | Meaning |
| ------------ | --------- |
| `name('exact')` | Exact name |
| `name(keyword: 'pat')` | Substring |
| `name(regex: '^HK-')` | Regular expression |
| `subtag('my-sub')` | Nodes produced by the exact tag in `subscription { ... }` |
| `subtag(regex: '^paid-', free)` | Subscription-tag regex or exact alternatives |
| `subtag('my-sub') && !name(keyword: 'ExpireAt-')` | AND predicates; `!` negates one predicate |
| `group('hk')` / `group('hk', 'jp')` | Nested groups |

Rules of thumb:

- No filters **and** no nested groups → include **all** nodes.
- Nested groups only → does **not** auto-include every node.
- Each `filter:` line is OR-ed. Predicates joined by `&&` inside one line are AND-ed; prefix a predicate with `!` to negate it.
- `name(...)` and `subtag(...)` matching is case-sensitive. `subtag` uses the subscription tag to the left of `:` and never matches static nodes.

**Policies:**

| Policy | Aliases | Behavior |
| -------- | --------- | ---------- |
| `selector` | `select`, `fixed` (e.g. `policy: fixed(0)`) | Manual pin |
| `urltest` | `min_moving_avg`, `min_avg10`, `min_last_delay` | Lowest latency + tolerance; TCP/UDP split |
| `loadbalance` | `roundrobin`, `round_robin`, `balance` | Round-robin alive members |
| `fallback` | | First alive sticky |

## 8. Routing

The `routing { ... }` section holds ordered rules, matched in **source order** (top to bottom), ending in a `fallback:`. A matcher's parenthesized argument list may span physical lines; it remains one rule through `-> outbound`:

```dae
routing {
    domain(suffix: doubleclick.net) -> block
    sip(10.10.10.24/32,
        10.10.10.25/32
    ) -> direct
    fallback: direct
}
```

Each rule is `condition [&& condition ...] -> outbound`. Available condition functions:

- `domain(...)` — args prefixed `suffix:`, `keyword:`, `full:`, `regex:`, `geosite:`; a bare argument is treated as a suffix.
- `dip(...)` / `sip(...)` — destination/source CIDRs; `dip` also accepts `geoip: <code>`.
- `dport(...)` / `sport(...)` — destination/source ports.
- `l4proto(...)` — `tcp` / `udp`.
- `pname(...)` — process names.
- `mac(...)`, `ipversion(...)`, `dscp(...)`.

Outbound targets: `direct`, `block`, any **group** or **node** name.

**Must rules** (`-> direct(must)`): match does not finalize; continues matching and propagates must semantics (Go dae compatible). Clash Global/Direct mode does not override must/block.

Geo assets: place `geoip.dat` / `geosite.dat` below `global.data_dir` for a
service-independent installation. An explicit `$DAE_LOCATION_ASSET` directory
takes precedence; the loader otherwise falls back to the working directory and
dae's standard asset directories. Geosite codes support dae's attribute filter:
`domain(geosite: category-games@cn)` keeps only entries carrying the `@cn`
attribute (key match is case-insensitive; everything after the first `@` is
the selector). A code that expands to zero matchers — unknown category or
unmatched attribute — logs a warning and never matches.

### Full routing snippet

```dae
routing {
    pname(dnsmasq) && l4proto(udp) && dport(53) -> direct(must)
    dip(geoip: private) -> direct(must)
    domain(geosite: geolocation-cn) -> direct
    domain(suffix: google.com) -> proxy
    fallback: direct
}
```

### When nodes fail (fail-closed semantics)

honk follows Go dae's fail-closed datapath: once health checking marks an
outbound dead, eBPF **drops** new flows routed to it (`TC_ACT_SHOT`). With a
single-node `fallback`, a dead node means all proxied traffic is dropped —
this is intentional (no silent direct leakage), not a bug. DNS to port 53
(TCP and UDP) is always exempted and still reaches the control plane, so a
direct-pinned DNS upstream keeps name resolution alive during an outage.

To keep the router itself reachable no matter what:

- honk auto-injects `dip(<every lan/wan interface address>) -> direct(must)`
  at startup and on each reload, so the admin UI / SSH / clash API never
  depend on node health.
- Add `dip(geoip: private) -> direct(must)` to cover the rest of the LAN
  (printers, other routers, NAS) — it costs nothing and matches dae's
  example config.
- For internet resilience, point `fallback` at a `fallback`-policy group
  with two or more nodes instead of a single node, and keep at least one
  DNS upstream on a direct path (e.g. `udp://223.5.5.5`).

## 9. DNS

```dae
dns {
    # Standalone listener is disabled unless bind is set.
    # bind: 'tcp+udp://:1053'
    ipversion_prefer: 4
    use_host: true

    upstream {
        alidns: 'udp://223.5.5.5:53'
        # optional: query this upstream via a proxy group
        googledns: 'tcp://8.8.8.8:53' -> proxy
        google_doh: 'https://dns.google/dns-query' -> proxy
    }

    routing {
        request {
            # qname / qtype / && / !  — same grammar as traffic routing
            qname(geosite: category-ads-all) -> reject
            qname(suffix: cn) -> alidns
            qtype(https) -> reject
            qtype(a, aaaa) -> alidns
            fallback: alidns   # also: asis | reject | named upstream
        }
        response {
            # accept | reject | named upstream (re-query, depth ≤ 3)
            upstream(googledns) -> accept
            ip(geoip: private) && !qname(geosite: cn) -> googledns
            fallback: accept
        }
    }

    fixed_domain_ttl {
        ddns.example.org: 10
        nocache.test: 0        # 0 = never cache
    }

    optimistic_cache: true
    # Fixed positive-cache TTL (overrides answer min TTL for cache + wire RR TTLs).
    # Set 0 to keep the upstream answer TTL instead.
    optimistic_cache_ttl: 600
    max_cache_size: 10000
}
```

`use_host` defaults to `false`. When enabled, honk loads `/etc/hosts` while
building each DNS runtime generation. Matching IN-class A/AAAA queries are
answered before request routing, cache lookup, or upstream exchange; a known
name without the requested address family returns NOERROR/NODATA. Other query
types continue through the normal pipeline. The snapshot is immutable on the
query path and is refreshed by SIGHUP; an unreadable file fails startup or the
new reload generation. Synthesized records advertise a 60-second TTL and are
not inserted into honk's DNS cache.

Upstream URIs take a scheme prefix: `udp://`, `tcp://`, `tcp+udp://`, `tls://`, `https://`, `quic://`, `h3://`; a bare `host:port` defaults to UDP.

### Standalone listener (`dns.bind`)

`bind` is optional. When it is absent or empty, only the standalone listener is
disabled; transparent TCP and UDP port-53 interception continues unchanged.
Accepted values are deliberately the current dae forms:

```dae
dns {
    bind: '127.0.0.1:1053'          # bare numeric IP:port: UDP only
    # bind: 'udp://localhost:1053'   # a hostname requires a scheme
    # bind: 'tcp://[::1]:1053'       # bracket IPv6 literals
    # bind: 'tcp+udp://:1053'        # empty host: wildcard, both transports
}
```

Every form requires an explicit port; port `0` asks the kernel for an ephemeral
port and the selected address is recorded in the startup log. A bare hostname
such as `localhost:1053` is invalid, as are userinfo, paths, queries, and
fragments. Hostnames are resolved in system order and the first address on
which every requested transport can bind is selected. IPv6 zone identifiers
are not supported; use a bracketed global, ULA, or loopback literal instead.

The listener uses ordinary, unmarked sockets in the host network namespace. A
LAN-facing local TCP or UDP listener on `:53` takes precedence for that
transport; a wildcard socket is eligible only for a host-local destination, so
queries to remote resolvers retain the transparent path. A wildcard or LAN
bind exposes a recursive resolver without application-layer authentication;
restrict it with host firewall policy and do not publish it to an untrusted
network.

Standalone requests use the same generation-pinned request/response routing,
cache, singleflight, upstream pools, and routing projection as transparent
requests. Only complete one-question DNS requests are admitted; a
multi-question UDP request receives FORMERR and a multi-question TCP stream is
closed before forwarding. UDP reply limits clamp the client EDNS size to
`512..=1232` bytes; wildcard replies preserve the queried local destination
address. TCP uses persistent RFC 7766 two-octet framing. Both transparent and
standalone TCP bound every length/body read and response write to 30 seconds;
the standalone listener also uses a cap no larger than one quarter of the
global connection budget.

Startup is all-or-nothing: every selected socket must bind before startup
succeeds, and any bind failure closes the other selected sockets and fails the
process. Listener ownership is process-scoped. A SIGHUP may reload the shared
DNS runtime, but a semantic `bind` change (host, port, or transport set) is
rejected as restart-required.
**Request outbounds:** named upstream, `reject` (empty success), or `asis`. For a transparent query, `asis` dials the intercepted original DNS destination using the client's transport; UDP retries the same destination over TCP when the response is truncated. Dial/connect timeout remains separate; after connection/session acquisition, the DNS query timeout is one absolute deadline covering the complete request write and response read for each attempt. A transport may retry once, so the aggregate remains bounded to two query attempts plus bounded reset/setup. A standalone query has no original destination, so `asis` returns a DNS failure instead of dialing the listener recursively.
**Response outbounds:** `accept`, `reject`, or a named upstream to re-query. All production service paths validate the exact question and complete response wire before cache publication.

**Caveats today:**

- DoT / DoH (HTTP/2) / DoQ / DoH3 are implemented with session reuse (TLS idle pool, H2 mux, single QUIC conn). DoQ/DoH3 do not yet support proxy tunneling.
- **Dial path (dae-aligned):**
  - Explicit: `name: 'uri' -> <node|group>` forces that outbound (GroupManager policy for groups).
  - Implicit (no `->`): resolve the DNS server IP/host, run the traffic `routing { }` rules on that destination, then select a leaf via GroupManager — same idea as dae's `chooseBestDnsDialer`.
  - H2/TLS sessions are cached **per leaf node**. Legacy `outbound: tag` is still accepted.
- Internal `sub()` / `node()` / `subnode()` request selectors are parsed and ignored (client DNS only).

**Compatibility and lifecycle:**

- Omitting `ipversion_prefer` keeps the actual `DnsConfig` default, `both`.
  Eligible A and AAAA work runs concurrently. Setting `4` or `6` selects the
  corresponding preference mode. Its sibling query preserves the caller's
  complete wire profile and changes only QTYPE.
- Cache and singleflight apply only to a standard one-question QUERY with no
  answer/authority records and at most one option-free EDNS-v0 OPT. Supported
  RD/AD/CD and DO state, exact question wire, UDP size, caller profile, policy,
  and logical destination are part of identity. Multi-question requests are
  rejected before policy planning. Unusual flags, EDNS options (including
  ECS/COOKIE), and EDNS-v1 requests still forward but bypass cache and
  coalescing.
- Reload publishes one coherent DNS runtime generation containing policy,
  routing, groups, transports, and projection. Existing requests keep their
  lease on the old generation while new requests use the replacement. Runtime
  retirement and pooled transport shutdown are bounded and awaited.
- DNS observability is internal. Independent monotonic atomic counters keep
  request recording non-blocking. An internal best-effort scrape loads fields
  separately and does not promise cross-counter coherence. Failure logs use
  bounded `error_kind` classes and bounded fields such as the transport label,
  without query names, upstream addresses, or free-form error payloads. This
  internal telemetry adds no public DNS metric or API.

## 10. Subscriptions

```dae
subscription {
    my-sub: 'https://example.com/sub'
}
```

Each entry is `tag: 'url'` (a bare quoted URL is also accepted). In dae syntax the subscription type, update interval, and enabled flag keep their defaults (auto/simple, 86400 s, enabled).

- `global { store_subscribe: true }` is the default. A successfully fetched and parsed raw body is atomically stored in `.sub` below `global.data_dir` with private permissions (`0700` directory, `0600` files). An existing legacy `./.sub` store is retained until moved. The cached body is never written back into the config, and request identity appears only as a hash filename.
- Startup restores valid stored bodies first. A restored subscription starts immediately while its network refresh continues in the background; an uncached subscription retains the five-second first-fetch grace period.
- SIGHUP reload carries active subscription nodes and restores the stored body when an enabled subscription has no nodes to carry. Fetch, parse, or write failure leaves the active nodes and last valid body untouched. A corrupt body is ignored until a valid refresh replaces it.
- Subscription nodes remain runtime-only and are never written back to the config file. Changing `store_subscribe` requires a process restart.
- Share links inside the body are parsed by `Node::from_share_link`.

Clash YAML VLESS entries map `uuid` (with legacy `password` fallback),
`encryption`, `servername` (with `sni` fallback), `flow`, and `network` before deriving the
node ID. Nested `reality-opts` maps `public-key`, `short-id`, and `spider-x`
(default `/`) and enables the REALITY TLS carrier; nested `ws-opts` maps
`path` plus a case-insensitive `headers.Host`, and `grpc-opts` maps
`grpc-service-name`. Existing flat WS/gRPC aliases remain accepted. A VLESS
entry with `reality-opts` but no non-empty `public-key` is skipped instead of
falling back to ordinary TLS. Clash `client-fingerprint` is intentionally
unmapped because honk selects the fingerprint process-wide.

The supported VLESS transport shapes are plain/TLS/REALITY over TCP, WS, or
gRPC, except that `xtls-rprx-vision` requires TLS or REALITY and TCP. Other
transports and flows are parsed for visibility but are not dialed by
`honk-tool sub`; VLESS has no UDP packet handler.

## 11. Experimental

### Held-first-packet UDP NFQUEUE

```dae
experimental {
    udp_nfqueue {
        enabled: true
    }
}
```

`enabled` is the only setting and defaults to `false`. Changing
`experimental.udp_nfqueue.enabled` is restart-required; a SIGHUP reload rejects
the change. Enabled startup requires a build with the `ebpf` feature and the
real eBPF backend. A build without `ebpf` or a run with `--mock-ebpf` is rejected
at startup rather than silently falling back.

This path covers **LAN-forwarded UDP only**: host `inet prerouting` follows the
LAN TC staging point, while host-originated WAN egress remains on the canonical
TPROXY path. Port 53, internal/special traffic, `must`, `block`, reverse traffic,
and already-safe route-time direct decisions are excluded. Only an ambiguous
decision that may still change after userspace routing or domain/QUIC inspection
is staged.

honk binds one raw-netlink NFQUEUE, fixed queue `320`, with no bypass, fanout, or
fail-open mode. It owns the exact nftables table and chain names
`inet honk_nfqueue` / `udp_decision`. A firewall manager in the same network
namespace must not flush, replace, or mutate either object while honk is running.
The eBPF `UDP_DECISION_SEQUENCE` pin is persistent across ordinary restart and
cleanup so a token is not reused while an old skb or task can still exist;
exhaustion requires a reboot.

The original skb is held before conntrack/NAT. Direct performs token-checked
Arm → FIFO `NF_ACCEPT` with the final mark → Activate, without a userspace direct
socket, payload copy, endpoint, connection entry, or deliberate retransmission.
Proxy commits token-bound state, transfers the one retained payload copy into
the existing UDP initializer, drops the original skb(s), and dials/sends once.
Block and cancellation drop the originals. Reload and shutdown clear readiness,
quiesce/cancel pending ownership, and only then tear down the queue and owned
table. Queue/listener/verdict errors and token exhaustion are fatal rather than
fail-open.

With the Clash API enabled, `GET /stats` exposes the fixed object
`/stats.udp.nfqueue` (dotted path, not a separate route): `received`,
`activeFlows`, `directAccepted`, `proxyCopied`, `proxyDropped`, `block`, `cancel`,
`drop`, `tokenMismatch`, `tokenExhaustion`, `verdictErrors`, and
`receiptToVerdict`. See the component reference for field meanings.

### Clash API

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'  # empty = disabled
        external_ui: 'yacd'
        secret: 'change-me'
        default_mode: 'Rule'                   # Rule | Global | Direct
    }
}
```

Useful endpoints: `/proxies`, `/proxies/{name}` (PUT selector), `/proxies/{name}/delay`, `/group/{name}/delay`, `/connections`, `/traffic`, `/logs`, `/dns/query`, `/stats`.

Env: `HONK_UI_DOWNLOAD_URL` overrides the default zashboard zip URL when `external_ui` is empty/missing. A relative `external_ui` prefers an existing directory below `global.data_dir`, then an existing working-directory-relative directory; a missing directory is created below `global.data_dir`. An absolute path is used unchanged. The download follows the traffic routing decision (Router + group selection): `direct` fetches directly, `block` aborts it, any other outbound is dialed through the selected node.

### Cache file

```dae
experimental {
    cache_file {
        enabled: true
        path: 'cache.db'
        cache_id: ''
        store_fakeip: false   # prefix/API only; full FakeIP engine incomplete
        store_dns: true       # persist DNS answers across restarts
    }
}
```

New relative `path` values resolve below `global.data_dir`; use an absolute path
to keep the database elsewhere. When `<global.data_dir>/<path>` does not exist,
an existing legacy path relative to the original config directory is retained
until moved.

Persists selector choices and clash mode. DNS answers use versioned `HDNS`
records under the `dns:v2:` key namespace. Upgrade starts this namespace cold:
legacy DNS rows are not imported or deleted. Restore accepts only unexpired,
well-formed rows with matching wire identity and policy. A pre-v2 rollback
ignores v2 rows, so they may remain safely in `cache.db`.

## 12. Running with a config

```bash
# Real eBPF (root)
sudo ./target/release/honk-core --config /etc/honk/config.dae

# External BPF object
sudo ./target/release/honk-core \
  --config /etc/honk/config.dae \
  --bpf-object /etc/honk/honk-ebpf.o

# Dev without kernel eBPF
cargo run --release -p honk-core -- \
  --config config.min.dae --mock-ebpf --debug
```

CLI flags: `--config` / `-c`, `--bpf-object` / `-b`, `--bpf-pin-root`, `--debug` / `-d`, `--mock-ebpf`.

Subcommands: `mode`, `proxy`, `delay` (see [components.en.md](./components.en.md)).

## 13. Validation tips

1. Prefer `config.dae` (or `config.min.dae`) as a starting point.
2. Ensure every `routing` fallback / rule target, `dns` fallback, and group `final:` name refers to a real group, node, `direct`, or `block`.
3. For domain rules on first connection, use `dial_mode: domain` / `domain++` or ensure DNS goes through honk so domain bitmaps fill.
4. After changing groups/policies, reload (SIGHUP) rebuilds `GroupManager`; selector choices migrate when still valid.
5. Changing `experimental.udp_nfqueue.enabled` requires a process restart; verify that an enabled deployment uses the real eBPF backend and that its firewall manager leaves `inet honk_nfqueue` / `udp_decision` alone.
6. Run `cargo test -p honk-config` to ensure examples still parse if you add fixtures.

## 14. Related docs

- [Design](./design.en.md)
- [DNS canary and rollback runbook](./dns-rollout.en.md)
- [Component reference](./components.en.md)
- Root examples: `config.dae`, `config.min.dae`
