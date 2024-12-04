use anyhow::Result;
use key_manager::cli::Cli;
use tracing::error;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .init();

    let cli = match Cli::new() {
        Ok(cli) => cli,
        Err(e) => {
            error!("{:?}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = cli.run() {
        error!("{:?}", e);
        std::process::exit(1);
    }
    Ok(())
}
