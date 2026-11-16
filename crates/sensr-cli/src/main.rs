//! `sensr` binary.

use clap::Parser;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let cli = sensr_cli::Cli::parse();
    let mut out = std::io::stdout().lock();
    match sensr_cli::run(cli, &mut out).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sensr: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
