use clap::Parser;
use honk_core::Cli;

/// musl's stock malloc is slow under contention; route all Rust
/// allocations through mimalloc in the shipped binary.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "mimalloc")]
fn mimalloc_collect_period(value: Option<&str>) -> Option<std::time::Duration> {
    let seconds = value.and_then(|value| value.parse().ok()).unwrap_or(60);
    (seconds > 0).then(|| std::time::Duration::from_secs(seconds))
}

#[cfg(feature = "mimalloc")]
std::thread_local! {
    static LAST_MI_COLLECT: std::cell::Cell<Option<std::time::Instant>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(feature = "mimalloc")]
fn collect_mimalloc_on_idle<F>(
    now: std::time::Instant,
    period: std::time::Duration,
    collect: F,
) -> bool
where
    F: FnOnce(),
{
    LAST_MI_COLLECT.with(|last_collect| match last_collect.get() {
        None => {
            last_collect.set(Some(now));
            false
        }
        Some(previous) if now.saturating_duration_since(previous) >= period => {
            last_collect.set(Some(now));
            collect();
            true
        }
        Some(_) => false,
    })
}

#[cfg(feature = "mimalloc")]
fn install_idle_collector<F>(
    builder: &mut tokio::runtime::Builder,
    period: std::time::Duration,
    collect: F,
) where
    F: Fn() + Send + Sync + 'static,
{
    builder.on_thread_park(move || {
        collect_mimalloc_on_idle(std::time::Instant::now(), period, &collect);
    });
}
fn block_on_worker<F, T>(runtime: &tokio::runtime::Runtime, future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    runtime.block_on(runtime.spawn(future))?
}

fn main() -> anyhow::Result<()> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    #[cfg(feature = "mimalloc")]
    {
        let value = std::env::var("HONK_MI_COLLECT_SECS").ok();
        if let Some(period) = mimalloc_collect_period(value.as_deref()) {
            install_idle_collector(&mut builder, period, || {
                // SAFETY: this hook runs on the worker that owns the default heap.
                unsafe { libmimalloc_sys::mi_collect(true) };
            });
        }
    }

    let runtime = builder.build()?;
    block_on_worker(&runtime, async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.command.is_some() {
        return honk_core::handle_clash_command(&cli).await;
    }

    honk_core::run(cli).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "mimalloc")]
    #[test]
    fn idle_collection_delays_first_park_and_obeys_per_thread_cooldown() {
        let start = std::time::Instant::now();
        let period = std::time::Duration::from_secs(10);
        let mut collections = 0;
        LAST_MI_COLLECT.with(|last_collect| last_collect.set(None));

        assert!(!collect_mimalloc_on_idle(start, period, || collections += 1));
        assert!(!collect_mimalloc_on_idle(
            start + std::time::Duration::from_secs(9),
            period,
            || collections += 1,
        ));
        let first_due = start + period;
        assert!(collect_mimalloc_on_idle(first_due, period, || {
            LAST_MI_COLLECT.with(|last_collect| assert_eq!(last_collect.get(), Some(first_due)));
            collections += 1;
        }));
        assert!(!collect_mimalloc_on_idle(
            first_due + std::time::Duration::from_secs(9),
            period,
            || collections += 1,
        ));
        assert!(collect_mimalloc_on_idle(first_due + period, period, || {
            collections += 1;
        }));

        assert_eq!(collections, 2);
        LAST_MI_COLLECT.with(|last_collect| last_collect.set(None));
    }

    #[cfg(feature = "mimalloc")]
    #[test]
    fn idle_collection_runs_on_each_worker_thread() {
        use parking_lot::{Condvar, Mutex};
        use std::collections::HashSet;
        use std::sync::{Arc, Barrier};

        let task_threads = Arc::new(Mutex::new(HashSet::new()));
        let collector_threads = Arc::new((Mutex::new(HashSet::new()), Condvar::new()));
        let callback_threads = Arc::clone(&collector_threads);

        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(4).enable_all();
        install_idle_collector(&mut builder, std::time::Duration::ZERO, move || {
            let (threads, wake) = &*callback_threads;
            threads.lock().insert(std::thread::current().id());
            wake.notify_all();
        });
        let runtime = builder.build().unwrap();

        let barrier = Arc::new(Barrier::new(5));
        let tasks = (0..4)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let task_threads = Arc::clone(&task_threads);
                runtime.spawn(async move {
                    task_threads.lock().insert(std::thread::current().id());
                    LAST_MI_COLLECT.with(|last_collect| {
                        last_collect.set(Some(std::time::Instant::now()));
                    });
                    barrier.wait();
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        runtime.block_on(async {
            for task in tasks {
                task.await.unwrap();
            }
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let (threads, wake) = &*collector_threads;
        let mut observed = threads.lock();
        while observed.len() < 4 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "not every runtime worker parked");
            let timeout = wake.wait_for(&mut observed, remaining);
            assert!(!timeout.timed_out() || observed.len() == 4);
        }

        assert_eq!(*task_threads.lock(), *observed);
    }
    #[test]
    fn top_level_future_runs_on_a_runtime_worker() {
        let caller = std::thread::current().id();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let worker = block_on_worker(&runtime, async {
            Ok::<_, anyhow::Error>(std::thread::current().id())
        })
        .unwrap();

        assert_ne!(caller, worker);
    }

    #[test]
    fn explicit_runtime_keeps_time_and_io_enabled() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let client = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), address.ip());
            client.await.unwrap().unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        });
    }
}
