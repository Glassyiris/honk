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

    honk_core::run(cli).await
}
