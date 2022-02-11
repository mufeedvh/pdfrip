use colored::*;

/// Logging message types
pub enum Type {
    _Warning,
    _Skipped,
    Error,
    Info,
    Success,
}

/// Outputs logging messages
pub fn push_message(log_type: Type, message: &str) {
    let prefix = match log_type {
        Type::_Warning => format!("{}{}{}", "[".bold(), "WARN".bold().yellow(), "]".bold()),
        Type::_Skipped => format!("{}{}{}", "[".bold(), "SKIPPED".bold().yellow(), "]".bold()),
        Type::Error => format!("\n{}{}{}", "[".bold(), "ERROR".bold().red(), "]".bold()),
        Type::Info => format!("{}{}{}", "[".bold(), "INFO".bold().cyan(), "]".bold()),
        Type::Success => format!("\n{}{}{}", "[".bold(), "SUCCESS".bold().green(), "]".bold())
    };

    eprint!("{}", format!("{} {}", prefix, message))
}