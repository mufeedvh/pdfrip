use std::process::ExitCode;

use pretty_env_logger::env_logger::Env;

fn init_logger() {
    let env = Env::default().filter_or("LOG_LEVEL", "info");
    pretty_env_logger::formatted_timed_builder()
        .parse_env(env)
        .init();
}

pub fn main() -> anyhow::Result<ExitCode> {
    init_logger();

    let cli_args = cli_interface::arguments::args();
    let code = cli_interface::entrypoint(cli_args)?;
    // We do this for cross-platform compatibility
    // since the meaning of exit code 0 depends on the platform...
    Ok(match code {
        cli_interface::Code::Success => ExitCode::SUCCESS,
        cli_interface::Code::Failure => ExitCode::FAILURE,
    })
}
