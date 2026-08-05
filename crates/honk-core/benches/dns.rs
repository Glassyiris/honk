use criterion::{criterion_group, criterion_main};

#[path = "dns/architecture.rs"]
mod architecture;
#[path = "dns/legacy.rs"]
mod legacy;
#[path = "dns/legacy_framing.rs"]
mod legacy_framing;

criterion_group!(
    benches,
    legacy::bench_endpoint_parse,
    legacy::bench_cache,
    legacy::bench_framing_id,
    legacy::bench_build_query,
    legacy::bench_forwarder_cache_hit,
    legacy::bench_tcp_pool_exchange,
    legacy::bench_udp_pool_exchange,
    legacy_framing::bench_length_prefix_roundtrip,
    architecture::bench_typed_key_build,
    architecture::bench_warmed_forwarder_hits,
    architecture::bench_projection_replacement,
    architecture::bench_policy_evaluation,
    architecture::bench_cache_concurrency,
    architecture::bench_singleflight,
    architecture::bench_parallel_families,
    architecture::bench_runtime_access,
    architecture::bench_observability,
    architecture::bench_allocation_harness,
);
criterion_main!(benches);
