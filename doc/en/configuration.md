# honk Configuration Guide

This guide shows how to assemble and operate a honk configuration without repeating the field inventories in the reference docs.

honk uses dae configuration syntax. The runtime sections and CLI entry point are listed below; `include {}` composes files and is covered next.

| Section | Purpose | Reference |
| --- | --- | --- |
| `global` | Select interfaces, dial behavior, health checks, and runtime paths. | [Global reference](./reference/global.md) |
| `node` | Declare static proxy nodes as share links. | [Node reference](./reference/nodes.md) |
| `group` | Select among nodes and nested groups. | [Group reference](./reference/groups.md) |
| `routing` | Apply ordered traffic rules and a fallback outbound. | [Routing reference](./reference/routing.md) |
| `dns` | Configure listeners, upstreams, request/response policy, and cache behavior. | [DNS reference](./reference/dns.md) |
| `subscription` | Fetch remote node lists. | [Subscription reference](./reference/subscription.md) |
| `experimental` | Enable the Clash API, persistent cache, or UDP NFQUEUE path. | [Experimental reference](./reference/experimental.md) |
| CLI | Select a config, backend, object file, or local command. | [CLI reference](./reference/cli.md) |

The built-in outbounds `direct` and `block` are injected at startup and may be used in groups and routing rules.

## Configuration format

- Put settings in `section { ... }` blocks as one `key: value` pair per line.
- Quote URLs, values containing whitespace, and values containing syntax characters such as `:`, `+`, or `#`. Scalar values plus `include` and `node` entries accept single or double quotes; use single quotes for quoted `subscription` URLs.
- Write lists accepted by a setting or matcher with commas: `lan_interface: eth0, eth1` or `dport(80, 443)`.
- Second-based durations accept bare seconds or `ms`, `s`, `m`, and `h` suffixes. Millisecond settings such as `check_tolerance` accept bare milliseconds, `ms`, or `s`.
- `#` starts a whole-line or unquoted trailing comment. Keep notes for `node` and `subscription` entries on separate comment lines.

### Splitting a configuration with `include {}`

```dae
include {
    config.d/*.dae
    'config.d/extra config.dae'
}
```

`include` entries may be bare or quoted and support `*`, `?`, and `[]` glob patterns. Patterns run in declaration order; each pattern's matches load in lexical order. Unmatched patterns, directories, and files without the `.dae` extension are skipped.

Every relative include, including one in a nested included file, resolves against the directory containing the entry config passed to `--config`. The loader canonicalizes the entry directory and every match; an absolute path or symlink target outside that directory is rejected. Loading the same canonical file twice, directly or through a cycle, is also rejected.

The entry file's own sections merge first regardless of where its `include` block appears, followed by each included file and its descendants. Later scalar keys override earlier values. Collection entries such as nodes, subscriptions, groups, DNS upstreams, fixed TTLs, and routing rules append in merge order.

## Runtime data directory

`global.data_dir` is the process-wide root for runtime state and relative runtime-supplied files. It defaults to `/var/share/honk`, must be a non-empty absolute path, and is restart-required. Relative `experimental.cache_file.path`, `experimental.clash_api.external_ui`, the `.sub` subscription store, `geoip.dat`, `geosite.dat`, and node `ech_config_path` resolve under it; absolute child paths stay literal. If the preferred data-directory copy is absent, honk retains an existing legacy cache beside the entry config, an existing `./.sub` store, or an existing working-directory UI/ECH path until it is moved. Geo lookup gives an existing `$DAE_LOCATION_ASSET/<file>` first priority, then checks `data_dir`, the working directory, and dae's standard asset directories.

See the [global reference](./reference/global.md).

## Minimal configuration

Replace `eth0` and the example node address before deployment. The comments give one purpose per setting or rule.

```dae
# Set the interception baseline.
global {
    # Follow the IPv4 default-route interface.
    wan_interface: auto
    # Intercept forwarded traffic from this LAN interface.
    lan_interface: eth0
    # Emit normal operational logs.
    log_level: info
    # Sniff domains and verify their destination IP.
    dial_mode: domain
    # Apply the recommended gateway sysctls.
    auto_config_kernel_parameter: true
    # Resolve proxy hostnames without self-interception.
    bootstrap_resolver: '1.1.1.1:53'
}

# Declare one static proxy node.
node {
    # Name the SOCKS5 share link `edge`.
    edge: 'socks5://192.0.2.2:1080'
}

# Turn the node into a selectable outbound.
group {
    proxy {
        # Include only the named node.
        filter: name('edge')
        # Pin the first matching member.
        policy: fixed(0)
    }
}

# Route private destinations directly and web traffic through the group.
routing {
    # Keep private destinations off the proxy.
    dip(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) -> direct(must)
    # Proxy common web ports.
    dport(80, 443) -> proxy
    # Send everything else directly.
    fallback: direct
}

# Keep DNS usable on a direct path.
dns {
    upstream {
        # Use a plain direct DNS server.
        public: 'udp://1.1.1.1:53' -> direct
    }
    routing {
        request {
            # Send unmatched questions to `public`.
            fallback: public
        }
    }
}
```

## Fuller configuration

This example combines a subscription, a static backup, a `subtag` filter, geo routing, proxied DoH, the Clash API, and persistent state.

```dae
global {
    wan_interface: auto
    lan_interface: br-lan
    log_level: info
    dial_mode: domain++
    auto_config_kernel_parameter: true
    data_dir: '/var/share/honk'
    bootstrap_resolver: '1.1.1.1:53'
    store_subscribe: true
}

node {
    backup: 'socks5://192.0.2.2:1080'
}

subscription {
    paid: 'https://subscription.example/sub'
}

group {
    proxy {
        filter: subtag('paid') && !name(keyword: 'ExpireAt-')
        filter: name('backup')
        policy: fallback
        final: block
    }
}

routing {
    dip(geoip: private) -> direct(must)
    domain(geosite: geolocation-cn) -> direct
    domain(geosite: geolocation-!cn) -> proxy
    fallback: proxy
}

dns {
    ipversion_prefer: 4
    upstream {
        direct_dns: 'udp://1.1.1.1:53' -> direct
        proxy_doh: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            qname(geosite: geolocation-cn) -> direct_dns
            fallback: proxy_doh
        }
        response {
            fallback: accept
        }
    }
}

experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'ui'
        secret: 'replace-me'
        default_mode: 'Rule'
    }
    cache_file {
        enabled: true
        path: 'cache.db'
        store_dns: true
    }
}
```

## Choosing interfaces

Set `lan_interface` to the interface or comma-separated interfaces receiving forwarded LAN traffic, and `wan_interface` to the interface carrying host-originated traffic. `auto` follows the IPv4 default-route interface; it stays pending rather than falling back to loopback when no default route exists, then reconciles on link, address, or route changes. For a WAN-only host proxy, omit `lan_interface`: configured WAN hooks still process host-originated TCP and UDP. Never add `lo` as a synthetic LAN interface.

See the [global reference](./reference/global.md).

## Choosing a dial mode

| Mode | When to use it |
| --- | --- |
| `ip` | Route only on IP metadata; disables domain sniffing. |
| `domain` | Default: sniff a domain, verify that it resolves to the destination IP, and dial by domain. |
| `domain+` | Sniff without the destination-IP reality check when client DNS does not pass through honk. |
| `domain++` | Force sniffing and re-run routing from SNI/HTTP Host. |

See the [global reference](./reference/global.md).

## Declaring nodes

Each `node` line is a share link: `tag: 'scheme://...'` or a bare quoted link. An explicit tag becomes the routing/API name and overrides a name embedded in the link; a bare link uses its fragment or a generated protocol/host name. Keep credentials, TLS/REALITY, transport, and protocol tuning in the link's userinfo and query parameters. Unparseable entries are skipped with a diagnostic, while removed protocols are hard configuration errors.

See the [node reference](./reference/nodes.md).

## Building groups

Use `filter: name(...)` for static names, `filter: subtag(...)` for subscription provenance, and `filter: group(...)` for nested groups. Predicates joined by `&&` are ANDed and `!` negates one predicate; separate `filter:` lines are ORed. No filters and no nested groups include all nodes, while nested groups alone do not. Choose `selector`/`fixed`, `urltest`/`min_moving_avg`, `loadbalance`/`roundrobin`, or `fallback`; set `final` for the all-dead result. Group dials always resolve to one leaf node.

See the [group reference](./reference/groups.md).

## Writing routing rules

Rules are source-ordered and use `matcher(...) [&& !matcher(...)] -> outbound`, followed by `fallback: outbound`. Targets are `direct`, `block`, a node, or a group. `direct(must)` marks a non-finalizing must decision that later matches carry forward; Clash Global/Direct mode never overrides `must` or `block`. Use `dip(geoip: private)`/`dip(geoip: cn)` for GeoIP and `domain(geosite: category)` for geosite data.

honk injects `dip(<every configured LAN/WAN interface address>) -> direct(must)` at startup and reload so gateway services do not depend on proxy health. Dead outbounds normally fail closed: new flows are dropped rather than leaked through `direct`. A TCP group with exactly one unique leaf and no `final` keeps that same proxy as a last resort; UDP and all-dead multi-leaf groups remain fail-closed. Keep `dip(geoip: private) -> direct(must)`, point internet `fallback` at a multi-member group with `policy: fallback` and an explicit fail-closed `final`, and keep at least one DNS upstream forced through `direct`.

See the [routing reference](./reference/routing.md).

## DNS setup

Upstream forms are bare `host:port` (UDP) or `udp://`, `tcp://`, `tcp+udp://`/`udp+tcp://`, `tls://`, `https://`, `quic://`, and `h3://`. Add `-> node-or-group` to force the dial path; TCP, UDP, DoT, and DoH can use a proxy outbound, while DoQ and DoH3 are direct-only. Request routing chooses `reject`, `asis`, or a named upstream; response routing chooses `accept`, `reject`, or a named upstream for a bounded re-query:

```dae
dns {
    upstream {
        secure: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            qname(suffix: example.org) && !qtype(aaaa) -> secure
            fallback: secure
        }
        response {
            upstream(secure) -> accept
            fallback: accept
        }
    }
}
```

Leave `bind` empty for transparent port-53 interception only. Standalone forms require an explicit port: bare numeric `IP:port` (UDP), `udp://host:port`, `tcp://host:port`, or `tcp+udp://host:port`; an empty host binds wildcard addresses. Bind loopback unless a host firewall protects LAN exposure. Omit `ipversion_prefer` for `both`, or set `4`/`6` to prefer that family.

See the [DNS reference](./reference/dns.md).

## Subscriptions

Declare each source as `tag: 'url'`; the tag is what `subtag(...)` matches. With the default `global.store_subscribe: true`, a successfully fetched and parsed raw body is atomically stored under `.sub`. Startup restores valid stored bodies before background refresh, SIGHUP carries active subscription nodes and restores storage only when no nodes survive, and fetch/parse/write failure preserves the active nodes and last valid body. Subscription nodes remain runtime-only. Changing `store_subscribe` requires a restart.

See the [subscription reference](./reference/subscription.md).

## Enabling the Clash API, cache file, and UDP NFQUEUE

**Clash API.** A non-empty `experimental.clash_api.external_controller` enables the server. Keep it on loopback unless a firewall and non-empty `secret` protect it; an empty secret disables API authentication. A relative `external_ui` resolves through `data_dir` and may be downloaded in the background when missing.

**Cache file.** Set `experimental.cache_file.enabled: true` to persist Selector choices and Clash mode; `store_dns: true` also persists eligible DNS answers. A relative `path` uses `data_dir`, subject to the legacy-path rule above.

**UDP NFQUEUE.** `experimental.udp_nfqueue.enabled: true` enables the held-first-packet path only for ambiguous LAN-forwarded UDP. It requires root, a build with `ebpf`, and the real backend; mock startup is rejected. The setting is restart-required and fail-closed. honk exclusively owns queue `320` and nftables `inet honk_nfqueue` / `udp_decision`; a firewall manager must not mutate them while honk runs.

See the [experimental reference](./reference/experimental.md) and [UDP NFQUEUE design](./design/nfqueue.md).

## Warm-up and dial budget

These mechanisms are independent and bounded by configured groups or explicit budgets rather than raw subscription size:

| Mechanism | Key | Default | Behavior |
| --- | --- | --- | --- |
| Bare TCP preconnect | `preconnect_node_count` | `'auto'` | One startup pass. `'auto'` tries up to 8 eligible nodes, group picks first; `0` disables it. Explicit `N` may cover all eligible nodes with at most 8 concurrent attempts. Session-owning AnyTLS/VLESS modes, QUIC, `direct`, and `block` are skipped. |
| Selector pin | — | Always on | Keeps every Selector's configured leaf warm, including an unhealthy explicit choice. It retains a reusable session/client or one bare server TCP as the protocol permits; choice changes and reload transfer ownership without cutting active flows. |
| UDP warm set | `udp_warm_node_count` | `0` | Takes the top `min(N,3)` UDP leaves per group and IP family, runs at most 4 attempts concurrently, and caps retained nodes at `4×N`. UDP and Selector ownership are independent. |
| Concurrent dial cap | `max_concurrent_dials` | `64` | Bounds physical proxy connects and handshakes per generation. Ready-pool hits, logical streams on warm transports, `direct`, and `block` are exempt; overlapping reload generations also share the startup descriptor gate. |

Health checks probe but never warm a cold node, so a large subscription does not create one idle tunnel per node.

See the [group selection design](./design/groups.md).

## Running

```bash
# Real eBPF with the embedded object.
sudo ./target/release/honk-core --config /etc/honk/config.dae

# Real eBPF with an external object.
sudo ./target/release/honk-core \
  --config /etc/honk/config.dae \
  --bpf-object /etc/honk/honk-ebpf.o

# Unprivileged development with the mock backend.
cargo run --release -p honk-core -- \
  --config config.min.dae --mock-ebpf --debug
```

See the [CLI reference](./reference/cli.md).

## Validation tips

1. Start from the repository's `config.min.dae` or `config.dae` and replace its interfaces, endpoints, and credentials.
2. Ensure every routing rule/fallback, DNS fallback, group `final`, and `->` proxy target names an existing group, node, `direct`, or `block` as appropriate.
3. For first-connection domain rules, use `dial_mode: domain`/`domain++` or ensure client DNS passes through honk so the domain routing map is populated.
4. After changing groups or policies, SIGHUP rebuilds `GroupManager`; a still-valid Selector choice migrates to the replacement generation.
5. Changing `experimental.udp_nfqueue.enabled` requires a restart; verify the real eBPF backend is active and the firewall manager leaves `inet honk_nfqueue` / `udp_decision` untouched.
6. When adding or changing configuration fixtures, run `cargo test -p honk-config` to keep parser examples valid.

## Related docs

- [Design overview](./design/overview.md)
- [Global configuration reference](./reference/global.md)
- [DNS rollout operations](./operations/dns-rollout.md)
