# honk-tool

`honk-tool` is the CLI toolbox for [honk](../..), containing diagnostics that
don't belong in the `honk-core` engine binary: subscription availability
checks, quick reads of the running engine's eBPF maps, and one-shot health
checks.

It is a **static musl binary** — it runs unprivileged where possible and on a
production gateway (VyOS/Debian) as a single copied file.

## Build

```bash
# Dev (glibc, your workstation)
cargo build --release -p honk-tool

# Static musl for the gateway (needs zig 0.14+, uses the ci/ wrappers)
ZIGCC_TARGET=x86_64-linux-musl \
CC_x86_64_unknown_linux_musl=$PWD/ci/zigcc \
CXX_x86_64_unknown_linux_musl=$PWD/ci/zigcxx \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$PWD/ci/zigcc \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
BINDGEN_EXTRA_CLANG_ARGS="$(ci/zig-bindgen-env x86_64-linux-musl)" \
cargo build --release -p honk-tool --target x86_64-unknown-linux-musl

scp target/x86_64-unknown-linux-musl/release/honk-tool vyos@<gateway>:/tmp/
```

> A gnu build fails to exec on musl-only systems ("No such file or
> directory" from the loader) — always deploy the musl build to the gateway.

## Commands

### `sub` — subscription availability check

```bash
honk-tool sub <url|file> [--target HOST:PORT] [--url TEST_URL]
              [--timeout SECS] [--concurrency N] [--limit N] [--ua UA]
              [--v4-target IP:PORT] [--v6-target [IP]:PORT]
```

Fetches a subscription (base64 / raw-line / Clash YAML, auto-detected) or
reads a local share-link file, prints the per-protocol breakdown, then probes
every node concurrently:

Defaults follow dae's `tcp_check_url` triple: `cp.cloudflare.com:80` as the
test host, `1.1.1.1:80` for v4 and `[2606:4700:4700::1111]:80` for v6 — so
the family probes work even when the resolver returns no AAAA (e.g.
`ipversion_prefer: 4`). Override with `--target/--v4-target/--v6-target`.

- server IP families (does the node host resolve to v4/v6?),
- proxied connectivity to the test host over **IPv4 and IPv6** — a full
  protocol dial through the node (TLS handshake included for TLS protocols),
- proxied latency via `urltest_node` (default target:
  `https://www.gstatic.com/generate_204`),
- UDP liveness: a minimal DNS A query **and** a real QUIC handshake (h3,
  certificates skipped) through the node's `dial_udp` — via the reusable
  `quic::quic_handshake_probe` in honk-outbound, which drives quinn over a
  custom `AsyncUdpSocket` on top of the tunnel.

Ends with alive-per-family counts and the median latency.

**v6 shows `no-AAAA`?** The v4/v6 probes resolve the test host and pick an
address of each family. When the resolver returns no AAAA (e.g. honk's DNS
with `ipversion_prefer: 4`, which suppresses AAAA answers), the v6 probe
reports `no-AAAA`. Pass explicit dae-style targets to skip DNS:
`--v4-target 1.1.1.1:443 --v6-target '[2606:4700:4700::1111]:443'`.

```text
$ honk-tool sub https://example.com/sub --limit 3
fetched 200 node(s) in 22ms
protocols: anytls×3

🇭🇰 hk.147   anytls   v4   v4: 41ms   v6: 0ms   urltest: 120ms
...
== 3 node(s): v4-proxied 3, v6-proxied 3, urltest-ok 3, median latency 120ms
```

### `bpf` — quick reads of the running engine's eBPF maps

```bash
honk-tool bpf show <map> [--ip ADDR] [--limit N] [--pin-root PATH]
honk-tool bpf stats [--pin-root PATH]
```

Reads the pinned maps under `/sys/fs/bpf` directly with raw `bpf(2)` calls
(no aya, no program loading) and decodes the kernel/userspace wire structs.
Requires root (or `CAP_BPF`).

`show` maps:

| name             | contents                                          |
| ---------------- | ------------------------------------------------- |
| `conn-state`     | conntrack entries with outbound/mark/must/state   |
| `redirect-track` | reply-rewrite tracking (outbound, from_wan, ifindex) |
| `domain-routing` | DNS-learned IP → rule-bitmap entries              |
| `routing-handoff`| pending eBPF → control-plane routing handoffs     |

`stats` prints the conn-state overflow counters, the `CONN_STATE_OCCUPANCY`
gauge (cumulative datapath inserts/deletes), and all non-zero per-outbound
tx/rx counters.

### `diagnose` — one-shot health check

```bash
honk-tool diagnose [--api http://127.0.0.1:9090] [--pin-root PATH] [--tproxy-mark 0x8000000]
```

Read-only checks, each printed as `[ok]` / `[FAIL]`:

1. engine process alive (`honk-core`/`dae` in `/proc`),
2. `daens` network namespace and `dae0` veth present,
3. daens fwmark policy-routing rule present,
4. required pinned maps present (`CONN_STATE_MAP`, `REDIRECT_TRACK`,
   `ROUTING_HANDOFF_MAP`, `CONN_STATE_OCCUPANCY`),
5. conn-state occupancy + overflow counters readable,
6. clash API reachable (`/version`).

Exits with `all checks passed` or `N issue(s) found`.

## Design notes

- Depends on `honk-config`, `honk-outbound`, `honk-ebpf-common`, and
  `honk-core` with `default-features = false` (no axum/aya pulled in).
- The map read path is a ~100-line libc `bpf(2)` layer instead of aya:
  aya's typed-map constructors and `sys` helpers are crate-private, so
  external tools can't open pinned maps through its public API. Note that
  `BPF_OBJ_GET` has its own attr layout (pathname at offset 0) that does
  not share the map-ops layout.
- Wire structs (`TuplesKey`, `ConnState`, …) carry `aya::Pod` impls in
  `honk-ebpf-common` for anything that does want the typed API.

## License

GPL-3.0-only, same as honk.
