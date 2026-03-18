use std::io::{self, Write};

use colored::*;

/// Writes the banner and binary version to the provided writer.
///
/// The banner is skipped by JSON mode so machine-readable output stays clean, but keeping this as a
/// separate helper makes the human CLI path easy to test and evolve.
pub fn write_banner<W: Write>(writer: &mut W) -> io::Result<()> {
    // Set the terminal to support ANSI escape codes on Windows.
    #[cfg(windows)]
    control::set_virtual_terminal(true).unwrap();

    writeln!(
        writer,
        "{}",
        format!(include_str!("banner.txt"), env!("CARGO_PKG_VERSION"))
            .bold()
            .red()
    )
}
