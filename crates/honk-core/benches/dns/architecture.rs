use std::alloc::System;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
use futures_util::future::join_all;
use honk_config::dns::{
    DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsRequestRouting, DnsRequestRule,
    DnsRouting, DnsStrategy,
};
use honk_core::dns::DnsResolver;
use honk_core::dns::bench_support::{
    CacheKeyBenchmarkInput, RuntimeBenchmark, observability_snapshot_checksum,
    record_observability_event,
};
use honk_core::dns::cache::DnsCache;
use honk_core::dns::forwarder::build_dns_query;
use honk_core::dns::routing::DnsRouter;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

#[path = "fixtures.rs"]
mod fixtures;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

pub(super) fn bench_typed_key_build(c: &mut Criterion) {
    let query = build_dns_query("www.example.com", 1);
    let input = CacheKeyBenchmarkInput::parse(&query);
    c.bench_function("dns_typed_key/build", |b| {
        b.iter(|| black_box(input.build()));
    });
}

pub(super) fn bench_policy_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_policy_evaluation");
    for count in [1_usize, 32, 128] {
        let router = router_with_rules(count);
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| black_box(router.select_request("benchmark.example", 1)));
        });
    }
    group.finish();
}

pub(super) fn bench_cache_concurrency(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let response = build_dns_query("hot.example", 1);
    let mut group = c.benchmark_group("dns_cache_tasks");
    for tasks in [1_usize, 16, 64] {
        for hit in [true, false] {
            let label = if hit { "hit" } else { "miss" };
            let keys = Arc::new(
                (0..tasks)
                    .map(|index| format!("{label}-{index}"))
                    .collect::<Vec<_>>(),
            );
            let caches = Arc::new(
                (0..tasks)
                    .map(|_| Arc::new(Mutex::new(DnsCache::new(1))))
                    .collect::<Vec<_>>(),
            );
            if hit {
                runtime.block_on(async {
                    for (cache, key) in caches.iter().zip(keys.iter()) {
                        cache.lock().await.put(key.clone(), response.clone(), 300);
                    }
                });
            }
            group.throughput(Throughput::Elements(tasks as u64));
            group.bench_with_input(
                BenchmarkId::new(label, tasks),
                &(tasks, hit),
                |b, &(tasks, _)| {
                    b.to_async(&runtime).iter(|| async {
                        let operations = (0..tasks).map(|index| {
                            let cache = Arc::clone(&caches[index]);
                            let keys = Arc::clone(&keys);
                            async move { cache.lock().await.get(&keys[index]) }
                        });
                        black_box(join_all(operations).await);
                    });
                },
            );
            if hit && tasks == 64 {
                group.bench_function(BenchmarkId::new("hit_sequential", tasks), |b| {
                    b.to_async(&runtime).iter(|| async {
                        for index in 0..tasks {
                            black_box(caches[index].lock().await.get(&keys[index]));
                        }
                    });
                });
            }
        }
    }
    group.finish();
}

pub(super) fn bench_singleflight(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let pool = Arc::new(fixtures::LoopbackPool::immediate());
    let forwarder = fixtures::forwarder(Arc::clone(&pool), true);
    let query = build_dns_query("singleflight.example", 1);
    let mut group = c.benchmark_group("dns_singleflight");
    group.sample_size(10);
    group.throughput(Throughput::Elements(128));
    group.bench_function("128_waiters", |b| {
        b.to_async(&runtime).iter(|| async {
            forwarder.cache().lock().await.clear();
            pool.reset_calls();
            let operations = (0..128).map(|_| forwarder.resolve(&query));
            black_box(join_all(operations).await);
            black_box(pool.calls());
        });
    });
    group.finish();
}

pub(super) fn bench_parallel_families(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let pool = Arc::new(fixtures::LoopbackPool::delayed());
    let forwarder = fixtures::forwarder(pool, false);
    let mut config = DnsConfig {
        strategy: DnsStrategy::Both,
        ..Default::default()
    };
    config.cache.enabled = false;
    let resolver =
        DnsResolver::with_forwarder(&config, Arc::clone(&forwarder)).expect("benchmark resolver");
    let slower_query = build_dns_query("parallel.example", 28);
    let mut group = c.benchmark_group("dns_parallel_families");
    group.sample_size(20);
    group.bench_function("slower_aaaa_branch", |b| {
        b.to_async(&runtime).iter(|| async {
            black_box(
                forwarder
                    .resolve(black_box(&slower_query))
                    .await
                    .expect("AAAA resolution"),
            );
        });
    });
    group.bench_function("a_and_aaaa", |b| {
        b.to_async(&runtime).iter(|| async {
            black_box(
                resolver
                    .resolve(black_box("parallel.example"))
                    .await
                    .expect("parallel resolution"),
            );
        });
    });
    group.finish();
}

pub(super) fn bench_runtime_access(c: &mut Criterion) {
    let runtime = Runtime::new().expect("benchmark runtime");
    let mut fixture = RuntimeBenchmark::new();
    let mut group = c.benchmark_group("dns_runtime_access");
    group.bench_function("lease_acquire", |b| {
        b.iter(|| black_box(fixture.acquire_generation()));
    });
    group.sample_size(10);
    group.bench_function("publish_swap", |b| {
        b.iter(|| {
            runtime.block_on(async {
                fixture.publish_next();
                black_box(fixture.acquire_generation());
            });
        });
    });
    group.finish();
    runtime.block_on(fixture.shutdown());
}

pub(super) fn bench_observability(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_observability");
    group.bench_function("record_event", |b| {
        b.iter(|| {
            record_observability_event();
        });
    });
    group.bench_function("best_effort_snapshot", |b| {
        b.iter(|| black_box(observability_snapshot_checksum()));
    });
    group.finish();
}

pub(super) fn bench_allocation_harness(c: &mut Criterion) {
    let response = build_dns_query("allocation.example", 1);
    let region = Region::new(GLOBAL);
    let measured_cache = populated_cache(&response);
    let allocated = region.change().bytes_allocated;
    eprintln!("DNS_ALLOC_10K_BYTES={allocated}");
    black_box(measured_cache);

    let mut group = c.benchmark_group("dns_allocation_harness");
    group.sample_size(10);
    group.throughput(Throughput::Elements(10_000));
    group.bench_function("cache_10k_entries", |b| {
        b.iter_batched(
            || Region::new(GLOBAL),
            |region| {
                let cache = populated_cache(&response);
                let allocated = region.change().bytes_allocated;
                black_box((cache, allocated));
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn populated_cache(response: &[u8]) -> DnsCache {
    let mut cache = DnsCache::new(10_000);
    for index in 0..10_000 {
        cache.put(format!("entry-{index}"), response.to_vec(), 300);
    }
    cache
}

fn router_with_rules(count: usize) -> DnsRouter {
    let rules = (0..count)
        .map(|index| DnsRequestRule {
            conditions: vec![DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Full(if index + 1 == count {
                    "benchmark.example".to_owned()
                } else {
                    format!("never-{index}.example")
                })],
            }],
            action: DnsRequestAction::Upstream("default".to_owned()),
        })
        .collect();
    DnsRouter::new(&DnsRouting {
        request: DnsRequestRouting {
            rules,
            fallback: DnsRequestAction::Reject,
        },
        ..Default::default()
    })
    .expect("benchmark router")
}
