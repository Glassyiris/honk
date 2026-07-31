# honk — eBPF transparent proxy engine
# https://github.com/Glassyiris/honk

# ── Default ──────────────────────────────────────────────
default: build

# ── Build ───────────────────────────────────────────────

# Build all workspace crates (release) — boring-sys needs cmake + a C
# compiler + libclang (bindgen) installed
build:
    cargo build --release

# Build honk-core with eBPF (clash-api is in the default features)
build-core:
    cargo build --release -p honk-core --features "ebpf"

# Build honk-core with eBPF only
build-core-ebpf:
    cargo build --release -p honk-core --features ebpf

# Build honk-core for VyOS/Debian (static musl, portable)
# Uses zig cc/c++ as the musl toolchain (ci/zigcc, ci/zigcxx): boring-sys
# (BoringSSL, C++) needs a clang-compatible compiler — under cross, CMake
# injects clang-style --target flags into the ASM rules that real GCC rejects
# ("unrecognized command-line option '--target=...'") and zig rejects in Rust
# triple spelling, so the wrappers strip them and re-anchor on the zig triple.
# link-self-contained=no lets zig supply the CRT (Rust's self-contained
# rcrt1.o + zig's crt1.o both define _start). Requires zig (0.14+) in PATH.
build-musl:
    ZIGCC_TARGET=x86_64-linux-musl \
    CC_x86_64_unknown_linux_musl={{justfile_directory()}}/ci/zigcc \
    CXX_x86_64_unknown_linux_musl={{justfile_directory()}}/ci/zigcxx \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER={{justfile_directory()}}/ci/zigcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
    BINDGEN_EXTRA_CLANG_ARGS="$({{justfile_directory()}}/ci/zig-bindgen-env x86_64-linux-musl)" \
    cargo build --release -p honk-core --features "ebpf" --target x86_64-unknown-linux-musl
    @echo "Binary: target/x86_64-unknown-linux-musl/release/honk-core"

# Build eBPF object standalone (optional; honk-core build.rs auto-builds it)
# NOTE: an environment RUSTFLAGS overrides crates/honk-ebpf/.cargo/config.toml
# rustflags (--btf, debuginfo) — the object then silently loses its .BTF
# section and aya refuses to load it ("no BTF parsed for object").
build-ebpf:
    @test -z "$RUSTFLAGS" || echo "warning: RUSTFLAGS is set and overrides crates/honk-ebpf/.cargo/config.toml (--btf) — the object may lack .BTF"
    cd crates/honk-ebpf && cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none
    @readelf -S crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf | grep -q '\.BTF' \
        || (echo "error: eBPF object has no .BTF section (see RUSTFLAGS note above)" && exit 1)

# Build all (core with embedded ebpf)
build-all: build-core

# ── Check ────────────────────────────────────────────────

# Fast compile check
check:
    cargo check

# Clippy lint all
lint:
    cargo clippy --all -- -D warnings

# Format all
fmt:
    cargo fmt --all

# ── Test ─────────────────────────────────────────────────

# Run all tests (includes known-failing pre-existing tests — see AGENTS.md)
test:
    cargo test --all

# CI-equivalent gate: full suite minus the known-failing pre-existing tests
# (share_link TOML round-trip ×2, config_dae_routing ×1 — see AGENTS.md)
test-ci:
    cargo test --workspace --no-fail-fast -- \
        --skip test_config_toml_round_trip \
        --skip test_to_file_and_from_file_by_extension \
        --skip test_routing_with_config_dae

# Run core + outbound tests
test-core:
    cargo test -p honk-core -p honk-outbound --lib

# Run config parser tests
test-config:
    cargo test -p honk-config --lib

# Run eBPF common tests
test-ebpf:
    cargo test -p honk-ebpf-common

# Root-gated netlink/netns integration tests (veth/route/rule roundtrip)
test-netns:
    cargo test -p honk-core --features ebpf --lib netns -- --ignored --test-threads=1

# Full honk-outbound gate after outbound changes (fmt + clippy + config & outbound suites)
outbound-ci:
    ci/outbound-ci.sh

# outbound-ci plus live hysteria2 e2e (needs HONK_HY2_SERVER=...)
outbound-ci-e2e:
    ci/outbound-ci.sh --with-e2e-env

# DNS subsystem gate (fmt + clippy + runtime/projection/resolver/control/outbound suites)
dns-ci:
    ci/dns-ci.sh

# Clash API gate (including Clash-only DNS query/flush scenarios)
clash-ci:
    ci/clash-ci.sh

# ── Run ──────────────────────────────────────────────────

# Run honk-core with eBPF (clash API comes from config.dae experimental section)
run-debug:
    cargo build --release -p honk-core --features "ebpf"
    @pkill honk-core 2>/dev/null || true
    @ip link del dae0 2>/dev/null || true
    @ip netns del daens 2>/dev/null || true
    @find /sys/fs/bpf -maxdepth 1 -type f -delete 2>/dev/null || true
    sleep 1
    RUST_LOG=info ./target/release/honk-core \
        --config config.dae \
        --bpf-object crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf

# Run honk-core with the example dae config
run-dae:
    cargo run --release -p honk-core --features ebpf -- --config config.dae --mock-ebpf

# ── Debug (clash API on :9090) ─────────────────────────────

# Query clash API version/status
debug-status:
    @curl -s http://localhost:9090/version | python3 -m json.tool && curl -s http://localhost:9090/configs | python3 -m json.tool

# Query proxy groups and selections
debug-config:
    @curl -s http://localhost:9090/proxies | python3 -m json.tool

# Query alive nodes and per-group delay
debug-alive:
    @curl -s 'http://localhost:9090/group/omg/delay?timeout=3000' | python3 -m json.tool

# Query per-outbound stats
debug-stats:
    @curl -s http://localhost:9090/stats | python3 -m json.tool

# Watch live connections (refresh every 2s)
watch-debug:
    watch -n2 'curl -s http://localhost:9090/connections | python3 -m json.tool'

# Show BPF program stats
bpf-progs:
    bpftool prog show 2>/dev/null | grep -E "lan_ingress|wan_egress|sk_lookup|dae0"

# Show BPF maps
bpf-maps:
    ls -la /sys/fs/bpf/ 2>/dev/null

# ── Clean ────────────────────────────────────────────────

# Clean build artifacts
clean:
    cargo clean

# Clean all honk-core state (process, netns, veth, bpf maps, policy routes).
# No iptables rules are installed by the live engine; the MASQUERADE/table-2023
# lines below only remove legacy leftovers.
clean-all:
    @echo "=== Stopping honk-core ==="
    @pkill honk-core 2>/dev/null || true
    @sleep 1
    @echo "=== Removing veth + netns ==="
    @ip link del dae0 2>/dev/null || true
    @ip netns del daens 2>/dev/null || true
    @echo "=== Cleaning BPF maps ==="
    @find /sys/fs/bpf -maxdepth 1 -type f -delete 2>/dev/null || true
    @echo "=== Cleaning policy routes (live: table 100) ==="
    @ip rule del fwmark 0x8000000/0x8000000 table 100 2>/dev/null || true
    @ip route flush table 100 2>/dev/null || true
    @echo "=== Cleaning legacy iptables/table-2023 leftovers ==="
    @iptables -t nat -D POSTROUTING -s 192.168.254.0/24 -j MASQUERADE 2>/dev/null || true
    @iptables -t nat -D POSTROUTING -s 169.254.0.0/16 -j MASQUERADE 2>/dev/null || true
    @ip rule del fwmark 0x8000000/0x8000000 table 2023 2>/dev/null || true
    @ip route flush table 2023 2>/dev/null || true
    @echo "=== Done ==="

# Deploy to VyOS router (static musl binary)
deploy-vyos HOST="10.10.10.1": build-musl
    scp target/x86_64-unknown-linux-musl/release/honk-core "root@{{ HOST }}:/config/vyos-scripts/podman/dae/dae"
    ssh "root@{{ HOST }}" 'chmod +x /config/vyos-scripts/podman/dae/dae && /config/vyos-scripts/podman/dae/dae --help'

# ── Dev ──────────────────────────────────────────────────

# Watch for changes and rebuild core
watch-core:
    cargo watch -x 'build --release -p honk-core --features ebpf'

# Full cycle: clean + core (auto-embeds ebpf)
cycle: clean-all build-core
    @echo "Ready to run: just run-debug"
