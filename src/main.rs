use std::process::ExitCode;

use anyhow::Context;
use engine::CancellationToken;
use pretty_env_logger::env_logger::Env;

fn init_logger() {
    let env = Env::default().filter_or("LOG_LEVEL", "warn");
    pretty_env_logger::formatted_timed_builder()
        .parse_env(env)
        .init();
}

fn install_ctrlc_handler(cancellation: CancellationToken, json: bool) -> anyhow::Result<()> {
    ctrlc::set_handler(move || {
        if !cancellation.is_cancelled() {
            cancellation.cancel();
            if !json {
                eprintln!("\nCancellation requested. Draining queued work before exiting...");
            }
        }
    })
    .context("failed to install Ctrl-C handler")
}

pub fn main() -> anyhow::Result<ExitCode> {
    let cli_args = cli_interface::arguments::args();
    init_logger();

    let cancellation = CancellationToken::new();
    install_ctrlc_handler(cancellation.clone(), cli_args.json)?;

    let code = cli_interface::entrypoint_with_cancellation(cli_args, cancellation)?;

    Ok(match code {
        cli_interface::Code::Success => ExitCode::SUCCESS,
        cli_interface::Code::Failure => ExitCode::FAILURE,
        cli_interface::Code::Cancelled => ExitCode::from(130),
    })
}
