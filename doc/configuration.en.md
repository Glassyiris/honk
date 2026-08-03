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

- Outbound **`direct`** is auto-injected if missing (usable in groups/filters/routing).
- Outbound **`block`** drops traffic.

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
| Intercept | `lan_interface`, `wan_interface` | Empty LAN list = no LAN intercept. `auto` resolves default-route iface (dae). |
| Listen | `tproxy_port` | Default `12345`; the TPROXY traffic mark defaults to `0x08000000`. |
| Kernel | `auto_config_kernel_parameter` | Needs root; enables helpful sysctls |
| Health | `tcp_check_url`, `udp_check_dns`, `check_interval`, `check_tolerance` | Drives AliveDialerSet / URLTest. Durations: `check_interval: 30s`, `check_tolerance: 50ms`. |
| Dial | `dial_mode` | `ip` / `domain` / `domain+` / `domain++` |
| Resolve | `bootstrap_resolver`, `fallback_resolver` | Avoid self-intercept when resolving node hostnames |

**Dial modes:**

| Value | When to use |
| ------- | ------------- |
| `ip` | Simple IP routing; no sniff |
| `domain` | Default; sniff + verify against dest IP |
| `domain+` | DNS does not go through honk |
| `domain++` | Force sniff and re-route on SNI/Host |

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
        filter: name(keyword: 'HK')
        filter: name('us1')
        filter: group('hk', 'jp')   # nested sub-groups (optional)
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
| `group('hk')` / `group('hk', 'jp')` | Nested groups |

Rules of thumb:

- No filters **and** no nested groups → include **all** nodes.
- Nested groups only → does **not** auto-include every node.
- Multiple `name(...)` filters OR together (one `filter:` line each).

**Policies:**

| Policy | Aliases | Behavior |
| -------- | --------- | ---------- |
| `selector` | `select`, `fixed` (e.g. `policy: fixed(0)`) | Manual pin |
| `urltest` | `min_moving_avg`, `min_avg10`, `min_last_delay` | Lowest latency + tolerance; TCP/UDP split |
| `loadbalance` | `roundrobin`, `round_robin`, `balance` | Round-robin alive members |
| `fallback` | | First alive sticky |

## 8. Routing

The `routing { ... }` section holds one rule per line, matched in **source order** (top to bottom), ending in a `fallback:`:

```dae
routing {
    domain(suffix: doubleclick.net) -> block
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

Geo assets: place `geoip.dat` / `geosite.dat` where the runtime can load them (repo root copies are common in dev). Geosite `@` attributes are written inline: `domain(geosite: category-games@cn)`.

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

- Startup fetch races a short deadline; late results merge via the control-plane channel.
- Subscription nodes live **in memory only** (not written back to the config file).
- Share links inside the body are parsed by `Node::from_share_link`.

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

Env: `HONK_UI_DOWNLOAD_URL` overrides the default zashboard zip URL when `external_ui` is empty/missing.

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
