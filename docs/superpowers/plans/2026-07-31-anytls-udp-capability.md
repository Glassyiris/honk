# AnyTLS network-aware UDP capability implementation plan

> **For AI workers:** Required sub-skill: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan. Track every step with the checkboxes below.

**Goal:** Prevent TCP-only AnyTLS nodes from being advertised, selected, or dialed as UDP warm-up work.

**Architecture:** Derive `OutboundCapabilities::udp` from both protocol support and the node's `network` allowlist. The control-plane warm candidate collector consumes that captured-generation capability, while AnyTLS retains a defensive `NotApplicable` check before any janitor or dial side effect.

**Tech stack:** Rust 2024, Tokio, inline crate unit tests, Cargo/Clippy.

---

## File responsibilities

- `crates/honk-outbound/src/runtime.rs` — authoritative per-node capability derivation and matrix tests.
- `crates/honk-outbound/src/proxy/anytls.rs` — generation-owned AnyTLS warm guard and no-dial regression test.
- `crates/honk-core/src/control/reload.rs` — authoritative warm candidate filtering and selection regression test.

### Task 1: Add RED capability and warm-up regressions

**Files:**
- Modify/test: `crates/honk-outbound/src/runtime.rs:253-268`
- Modify/test: `crates/honk-outbound/src/proxy/anytls.rs:3575-3616`
- Modify/test: `crates/honk-core/src/control/reload.rs:1422-1490`

- [ ] **Step 1: Extend the runtime capability matrix with network allowlists**

Add these assertions to `capabilities_matrix`:

```rust
let mut tcp_only_anytls = node("tcp-only", NodeProtocol::AnyTLS);
tcp_only_anytls.network = Some("tcp".into());
assert!(!OutboundCapabilities::for_node(&tcp_only_anytls).udp);

let mut mixed_anytls = node("mixed", NodeProtocol::AnyTLS);
mixed_anytls.network = Some(" TCP, UDP ".into());
assert!(OutboundCapabilities::for_node(&mixed_anytls).udp);
```

- [ ] **Step 2: Add a no-side-effect AnyTLS warm guard test**

Add this test beside the existing warm ownership tests:

```rust
#[tokio::test]
async fn warm_udp_tcp_only_runtime_is_not_applicable_without_dialing() {
    let node = Node {
        name: "tcp-only-anytls".into(),
        protocol: NodeProtocol::AnyTLS,
        network: Some("tcp".into()),
        anytls_min_idle_session: Some(0),
        ..Default::default()
    };
    let generation = Arc::new(
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
    );
    let runtime = generation.get(&node.id).unwrap();
    let dials = Arc::new(AtomicUsize::new(0));
    let dial_count = Arc::clone(&dials);

    let status = AnyTlsHandler::warm_pool_with(
        runtime,
        Duration::from_secs(1),
        move || async move {
            dial_count.fetch_add(1, Ordering::AcqRel);
            anyhow::bail!("TCP-only runtime must not dial for UDP warm-up")
        },
    )
    .await
    .unwrap();

    assert_eq!(status, UdpWarmStatus::NotApplicable);
    assert_eq!(dials.load(Ordering::Acquire), 0);
}
```

- [ ] **Step 3: Add a warm-candidate filtering test**

Add this test beside `udp_warm_candidates_only_use_authoritative_group_leaves`:

```rust
#[test]
fn udp_warm_candidates_exclude_tcp_only_anytls_runtime() {
    let make_node = |name: &str, network: &str| Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        protocol: honk_config::types::NodeProtocol::AnyTLS,
        address: "127.0.0.1:9".into(),
        network: Some(network.into()),
        ..Default::default()
    };
    let tcp_only = make_node("tcp-only", "tcp");
    let udp_enabled = make_node("udp-enabled", "tcp,udp");
    let config = Config {
        nodes: vec![tcp_only.clone(), udp_enabled.clone()],
        groups: vec![
            Group {
                name: "tcp-only-group".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![tcp_only.id],
                ..Default::default()
            },
            Group {
                name: "udp-group".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![udp_enabled.id],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let generation =
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

    assert_eq!(
        udp_warm_candidates(&config, &manager, &generation, usize::MAX),
        vec![udp_enabled.id]
    );
}
```

- [ ] **Step 4: Run the three tests and verify RED**

Run:

```bash
cargo test -p honk-outbound capabilities_matrix
cargo test -p honk-outbound warm_udp_tcp_only_runtime_is_not_applicable_without_dialing
cargo test -p honk-core udp_warm_candidates_exclude_tcp_only_anytls_runtime
```

Expected: all three new expectations fail for the missing network-aware capability behavior; compilation itself remains clean.

### Task 2: Implement the minimum network-aware behavior

**Files:**
- Modify: `crates/honk-outbound/src/runtime.rs:36-56`
- Modify: `crates/honk-outbound/src/proxy/anytls.rs:1284-1311`
- Modify: `crates/honk-core/src/control/reload.rs:403-439`

- [ ] **Step 1: Intersect protocol support with the network allowlist**

In `OutboundCapabilities::for_node`, retain the existing protocol matrix as `protocol_udp`, then derive the final capability:

```rust
let network_udp = node.network.as_deref().is_none_or(|network| {
    network
        .split(',')
        .any(|entry| entry.trim().eq_ignore_ascii_case("udp"))
});
let udp = protocol_udp && network_udp;
```

- [ ] **Step 2: Make AnyTLS warm-up fail closed before side effects**

Change the first guard in `warm_pool_with` to:

```rust
if runtime.node.protocol != NodeProtocol::AnyTLS || !runtime.capabilities.udp {
    return Ok(UdpWarmStatus::NotApplicable);
}
```

This check must remain before pool extraction, `ensure_janitor`, and `pool.offer`.

- [ ] **Step 3: Filter warm candidates through the captured runtime capability**

Replace the generation-presence-only check in `udp_warm_candidates` with:

```rust
let Some(runtime) = generation.get(&node.id) else {
    continue;
};
if !runtime.capabilities.udp {
    continue;
}
```

- [ ] **Step 4: Re-run the RED tests and verify GREEN**

Run the three commands from Task 1 Step 4.

Expected: all tests pass; the AnyTLS test records zero dials and candidate discovery returns only the UDP-enabled UUID.

### Task 3: Validate and commit

- [ ] **Step 1: Run formatting, diagnostics, and focused crate gates**

```bash
cargo fmt --all -- --check
cargo clippy -p honk-outbound -p honk-core --all-targets -- -D warnings
cargo test -p honk-outbound capabilities
cargo test -p honk-outbound warm_udp
cargo test -p honk-core udp_warm_candidates
```

Expected: every command exits successfully with no warnings.

- [ ] **Step 2: Run project CI-equivalent gates**

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY ci/outbound-ci.sh
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY ci/dns-ci.sh
```

Expected: both scripts pass, including honk-config, honk-outbound, DNS/control, and Clippy gates.

- [ ] **Step 3: Inspect the final patch**

```bash
git diff --check
git diff -- crates/honk-outbound/src/runtime.rs \
  crates/honk-outbound/src/proxy/anytls.rs \
  crates/honk-core/src/control/reload.rs
```

Expected: only the approved network-aware capability, defensive guard, candidate filter, and tests are present.

- [ ] **Step 4: Commit atomically**

```bash
git add crates/honk-outbound/src/runtime.rs \
  crates/honk-outbound/src/proxy/anytls.rs \
  crates/honk-core/src/control/reload.rs
git commit -m "fix(udp): skip TCP-only AnyTLS warm-up"
```
