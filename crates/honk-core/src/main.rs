use clap::Parser;
use honk_core::Cli;

/// musl's stock malloc is slow under contention; route all Rust
/// allocations through mimalloc in the shipped binary.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.command.is_some() {
        return honk_core::handle_clash_command(&cli).await;
    }

    // Purged pages pinned by a few live fragments linger between
    // collections; a periodic full collect keeps RSS near the live working
    // set instead of the traffic high-water mark. HONK_MI_COLLECT_SECS=0
    // disables it (benchmarks, p99-sensitive deployments).
    #[cfg(feature = "mimalloc")]
    {
        let period_secs: u64 = std::env::var("HONK_MI_COLLECT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        if period_secs > 0 {
            tokio::spawn(async move {
                let period = std::time::Duration::from_secs(period_secs);
                // A plain interval fires its first tick immediately — a
                // forced collect during cold start would land right on the
                // first handshakes, so start one period out.
                let mut tick =
                    tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    // The collect walks every arena; keep that off the
                    // runtime workers or it shows up as a periodic p99 blip.
                    tokio::task::spawn_blocking(|| {
                        // SAFETY: mi_collect is safe to call from any thread.
                        unsafe { libmimalloc_sys::mi_collect(true) };
                    });
                }
            });
        }
    }

    honk_core::run(cli).await
}
