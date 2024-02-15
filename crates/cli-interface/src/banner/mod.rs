use colored::*;

/// Prints a cool banner along with binary version
pub fn banner() {
    // Set the terminal to support ANSI escape codes on Windows
    #[cfg(windows)]
    control::set_virtual_terminal(true).unwrap();

    // We also make sure to grab the binary version from Cargo.toml
    println!(
        "{}",
        format!(include_str!("banner.txt"), env!("CARGO_PKG_VERSION"))
            .bold()
            .red()
    );
}
