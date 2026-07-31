//! Candidate-only synchronous UDP micro-benchmarks.
//!
//! These report Criterion's mean/median/MAD and absolute throughput for the
//! current candidate. They are not a source-level A/B comparison and do not
//! claim a p95 estimate.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use honk_core::control::udp_endpoint::bench_support;
use honk_core::stats::StatsManager;
use std::hint::black_box;
use std::time::Duration;

const STEADY_ENQUEUE_ITERATIONS: usize = 1_000_000;
const RESERVE_ROLLBACK_ITERATIONS: usize = 10_000;
const HISTOGRAM_ITERATIONS: usize = 1_000_000;
const QUEUE_SATURATION_OPERATIONS: u64 = 65;

fn bench_steady_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_steady_enqueue_128b");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(128 * STEADY_ENQUEUE_ITERATIONS as u64));
    group.bench_function("one_million", |b| {
        b.iter(|| bench_support::steady_enqueue_128_batch(black_box(STEADY_ENQUEUE_ITERATIONS)));
    });
    group.finish();
}

fn bench_reserve_rollback(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_reserve_rollback");
    group.sample_size(10);
    group.throughput(Throughput::Elements(RESERVE_ROLLBACK_ITERATIONS as u64));
    group.bench_function("ten_thousand", |b| {
        b.iter(|| bench_support::reserve_rollback_batch(black_box(RESERVE_ROLLBACK_ITERATIONS)));
    });
    group.finish();
}

fn bench_histogram_record_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_histogram_record_snapshot");
    group.sample_size(10);
    group.throughput(Throughput::Elements(HISTOGRAM_ITERATIONS as u64));
    group.bench_function("one_million", |b| {
        b.iter(|| {
            let stats = StatsManager::new();
            let latency = Duration::from_nanos(128);
            for _ in 0..HISTOGRAM_ITERATIONS {
                stats.record_udp_route_latency(latency);
            }
            let snapshot = stats.udp_snapshot();
            assert_eq!(snapshot.route_latency.count, HISTOGRAM_ITERATIONS as u64);
            black_box(snapshot);
        });
    });
    group.finish();
}

fn bench_queue_saturation(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_queue_saturation");
    group.sample_size(10);
    group.throughput(Throughput::Elements(QUEUE_SATURATION_OPERATIONS));
    group.bench_function("64_admitted_then_drop_newest", |b| {
        b.iter(bench_support::queue_saturation_batch);
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_steady_enqueue,
    bench_reserve_rollback,
    bench_histogram_record_snapshot,
    bench_queue_saturation,
);
criterion_main!(benches);
