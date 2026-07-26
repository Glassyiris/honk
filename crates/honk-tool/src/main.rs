//! honk-tool — CLI toolbox for honk diagnostics.
//!
//! Currently implemented: `sub` (subscription availability check).

mod sub;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "honk-tool", version, about = "honk CLI toolbox")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a subscription and probe every node: server families, per-family
    /// proxy connectivity, and proxied latency.
    Sub(sub::SubArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Sub(args) => sub::run(args).await,
    }
}
