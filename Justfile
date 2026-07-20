# honk — eBPF transparent proxy engine
# https://github.com/Glassyiris/honk

# ── Default ──────────────────────────────────────────────
default: build

# ── Build ───────────────────────────────────────────────

# Build all workspace crates (release)
build:
    cargo build --release

# Build honk-core with eBPF (clash-api is in the default features)
build-core:
    cargo build --release -p honk-core --features "ebpf"

# Build honk-core with eBPF only
build-core-ebpf:
    cargo build --release -p honk-core --features ebpf

# Build honk-core for VyOS/Debian (static musl, portable)
build-musl:
    cargo build --release -p honk-core --features "ebpf" --target x86_64-unknown-linux-musl
    @echo "Binary: target/x86_64-unknown-linux-musl/release/honk-core"

# Build eBPF object standalone (optional; honk-core build.rs auto-builds it)
build-ebpf:
    cd crates/honk-ebpf && cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none

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

# Run all tests
test:
    cargo test --all

# Run core + outbound tests
test-core:
    cargo test -p honk-core -p honk-outbound --lib

# Run config parser tests
test-config:
    cargo test -p honk-config --lib

# Run eBPF common tests
test-ebpf:
    cargo test -p honk-ebpf-common

# ── Run ──────────────────────────────────────────────────

# Run honk-core with config.dae (local testing)
run:
    ./scripts/debug-local.sh

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

# ── Deploy ────────────────────────────────────────────────

# Deploy to gateway (default: 10.10.10.1)
deploy HOST="10.10.10.1": build-ebpf build-core
    @./scripts/deploy-gateway.sh {{ HOST }}

# ── Clean ────────────────────────────────────────────────

# Clean build artifacts
clean:
    cargo clean

# Clean all honk-core state (process, netns, veth, bpf maps, iptables, routes)
clean-all:
    @echo "=== Stopping honk-core ==="
    @pkill honk-core 2>/dev/null || true
    @sleep 1
    @echo "=== Removing veth + netns ==="
    @ip link del dae0 2>/dev/null || true
    @ip netns del daens 2>/dev/null || true
    @echo "=== Cleaning BPF maps ==="
    @find /sys/fs/bpf -maxdepth 1 -type f -delete 2>/dev/null || true
    @echo "=== Cleaning iptables rules ==="
    @iptables -t nat -D POSTROUTING -s 192.168.254.0/24 -j MASQUERADE 2>/dev/null || true
    @iptables -t nat -D POSTROUTING -s 169.254.0.0/16 -j MASQUERADE 2>/dev/null || true
    @echo "=== Cleaning policy routes ==="
    @ip rule del fwmark 0x8000000/0x8000000 table 2023 2>/dev/null || true
    @ip route flush table 2023 2>/dev/null || true
    @echo "=== Done ==="

# Deploy to VyOS router (static musl binary)
deploy-vyos HOST="10.10.10.1": build-musl
    scp target/x86_64-unknown-linux-musl/release/honk-core "root@{{ HOST }}:/config/vyos-scripts/podman/dae/dae"
    ssh "root@{{ HOST }}" 'chmod +x /config/vyos-scripts/podman/dae/dae && /config/vyos-scripts/podman/dae/dae --help'

# ── Docker ───────────────────────────────────────────────

# Build Docker image
docker:
    docker build -t honk:latest .

# Run with Docker Compose
docker-up:
    docker compose up -d

# Stop Docker Compose
docker-down:
    docker compose down

# ── Dev ──────────────────────────────────────────────────

# Watch for changes and rebuild core
watch-core:
    cargo watch -x 'build --release -p honk-core --features ebpf'

# Full cycle: clean + core (auto-embeds ebpf)
cycle: clean-all build-core
    @echo "Ready to run: just run-debug"
