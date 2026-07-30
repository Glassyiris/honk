use clap::Parser;
use honk_core::Cli;

/// musl's stock malloc is slow under contention; route all Rust
/// allocations through mimalloc in the shipped binary.
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
    // set instead of the traffic high-water mark.
    tokio::spawn(async {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            // SAFETY: mi_collect is safe to call from any thread.
            unsafe { libmimalloc_sys::mi_collect(true) };
        }
    });

    honk_core::run(cli).await
}
