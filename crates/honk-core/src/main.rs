use clap::Parser;
use honk_core::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.command.is_some() {
        return honk_core::handle_clash_command(&cli).await;
    }

    honk_core::run(cli).await
}
