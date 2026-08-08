# honk Configuration Guide

This guide covers how to configure **honk**: the configuration format, top-level sections, and common examples.

For field-by-field component details (every node/group/DNS/CLI option), see [components.en.md](./components.en.md).

## 1. Configuration format

honk is configured in the **dae configuration syntax** — the original `{ section { ... } }` language used by [dae](https://github.com/daeuniverse/dae):

- Configuration is organized into **sections**: `include { ... }`, `global { ... }`, `node { ... }`, `group { ... }`, `routing { ... }`, `dns { ... }`, `subscription { ... }`, `experimental { ... }`.
- Inside non-`include` sections, settings are `key: value` pairs, one per line.
- Strings containing special characters (URLs, `+`, `//`, `:`) should be **quoted** (single or double quotes both work): `tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'`.
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

## 2. Top-level structure

```text
include { ... }        # merge additional .dae configuration files
global { ... }         # transparent proxy, health checks, dial mode, timeouts
node { ... }           # static proxy nodes (share links)
group { ... }          # selection policies over nodes / nested groups
routing { ... }        # ordered traffic rules + fallback outbound
dns { ... }            # upstreams, DNS routing, cache
subscription { ... }   # remote node lists
experimental { ... }   # clash_api, cache_file
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
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'
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
    tcp_check_url: 'http://cp.cloudflare.com'
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

honk warms up in three distinct ways, all budgeted — none of them scales
with raw node count, so large subscriptions are safe:

| Mechanism | Key | Default | Notes |
| ----------- | ----- | --------- | ------- |
| Bare TCP preconnect at startup | `preconnect_node_count` | `'auto'` | `'auto'` = up to 8 nodes (each group's current pick first, then config order); `0` disables; `N` pins the count. Only bare-TCP-poolable protocols qualify — AnyTLS/QUIC and the built-in `direct`/`block` are always skipped. |
| TCP/TLS warm set | `tcp_warm_node_count` | `1` | Keeps the K fastest AnyTLS/TCP leaves per group per IP family warm. With few nodes (<50) `3`-`5` noticeably cuts first-hit latency on off-winner chains; with large subscriptions keep `1`-`2`. |
| UDP warm set | `udp_warm_node_count` | `0` | Top-N UDP leaves per group per IP family; the process-wide total is capped at `4×N`, so many groups cannot blow the budget. |
| Concurrent dial cap | `max_concurrent_dials` | `64` | Bounds concurrent proxied dials (connect + handshake) per generation. Built-in `direct`/`block` dials are exempt (local connects). Reload changes the replacement's local limit, while old and new generations share one immutable startup descriptor gate. |

Health checks probe but never warm: a probe on a cold node leaves no
session behind, so `check_interval` on a 400-node subscription does not
create 400 idle tunnels. `/stats` exposes the live warm inventory under
`warm` (reason × hot-node count, sessions per protocol).

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

Geo assets: place `geoip.dat` / `geosite.dat` where the runtime can load them (repo root copies are common in dev). Geosite codes support dae's attribute filter: `domain(geosite: category-games@cn)` keeps only entries carrying the `@cn` attribute (key match is case-insensitive; everything after the first `@` is the selector). A code that expands to zero matchers — unknown category or unmatched attribute — logs a warning and never matches.

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
    ipversion_prefer: 4

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

Upstream URIs take a scheme prefix: `udp://`, `tcp://`, `tcp+udp://`, `tls://`, `https://`, `quic://`, `h3://`; a bare `host:port` defaults to UDP.

**Request outbounds:** named upstream, `reject` (empty success), `asis` (dial the intercepted original DNS destination).
**Response outbounds:** `accept`, `reject`, or a named upstream to re-query.

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
  corresponding preference mode; it does not add a new configuration surface.
- Cache and singleflight apply only to a standard one-question QUERY with no
  answer/authority records and at most one option-free EDNS-v0 OPT. Supported
  RD/AD/CD and DO state, exact question wire, UDP size, caller profile, policy,
  and logical destination are part of identity. Multi-question, unusual flags,
  EDNS options (including ECS/COOKIE), and EDNS-v1 requests still forward but
  bypass cache and coalescing.
- Reload publishes one coherent DNS runtime generation containing policy,
  routing, groups, transports, and projection. Existing requests keep their
  lease on the old generation while new requests use the replacement. Runtime
  retirement and pooled transport shutdown are bounded and awaited.
- DNS observability is internal. Independent monotonic atomic counters keep
  request recording non-blocking. An internal best-effort scrape loads fields
  separately and does not promise cross-counter coherence. Failure logs use
  bounded `error_kind` classes and bounded fields such as the transport label,
  without query names, upstream addresses, or free-form error payloads. No
  DNS endpoint, config key, or API was added.

## 10. Subscriptions

```dae
subscription {
    my-sub: 'https://example.com/sub'
}
```

Each entry is `tag: 'url'` (a bare quoted URL is also accepted). In dae syntax the subscription type, update interval, and enabled flag keep their defaults (auto/simple, 86400 s, enabled).

- `global { store_subscribe: true }` is the default. A successfully fetched and parsed raw body is atomically stored under `<working-directory>/.sub` with private permissions (`0700` directory, `0600` files). The cached body is never written back into the config, and request identity appears only as a hash filename.
- Startup restores valid stored bodies first. A restored subscription starts immediately while its network refresh continues in the background; an uncached subscription retains the five-second first-fetch grace period.
- SIGHUP reload carries active subscription nodes and restores the stored body when an enabled subscription has no nodes to carry. Fetch, parse, or write failure leaves the active nodes and last valid body untouched. A corrupt body is ignored until a valid refresh replaces it.
- Subscription nodes remain runtime-only and are never written back to the config file. Changing `store_subscribe` requires a process restart.
- Share links inside the body are parsed by `Node::from_share_link`.

Clash YAML VLESS entries map `uuid` (with legacy `password` fallback),
`servername` (with `sni` fallback), `flow`, and `network` before deriving the
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

Env: `HONK_UI_DOWNLOAD_URL` overrides the default zashboard zip URL when `external_ui` is empty/missing. The download follows the traffic routing decision (Router + group selection): `direct` fetches directly, `block` aborts it, any other outbound is dialed through the selected node.

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
5. Run `cargo test -p honk-config` to ensure examples still parse if you add fixtures.

## 14. Related docs

- [Design](./design.en.md)
- [DNS canary and rollback runbook](./dns-rollout.en.md)
- [Component reference](./components.en.md)
- Root examples: `config.dae`, `config.min.dae`
