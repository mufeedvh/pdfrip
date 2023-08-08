use clap::{ArgGroup, Parser};
use colored::*;

pub fn banner() {
    eprintln!("{}", include_str!("banner").bold().red())
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(group(ArgGroup::new("actions").required(true).args(&["wordlist", "num-bruteforce", "date-bruteforce", "custom-query"])))]
/// A fast PDF password cracking utility written in Rust.
pub struct Arguments {
    #[clap(short, long)]
    /// The filename of the PDF
    pub filename: String,

    #[clap(short, long)]
    /// Path to the pasword wordlist.
    pub wordlist: Option<String>,

    #[clap(short, long)]
    /// Bruteforce numbers for the password with the given range.\n\nlike `-n 0-1000000`
    pub num_bruteforce: Option<String>,

    #[clap(short, long)]
    /// Enabling this adds preceding zeros to number ranges in custom queries.\n\nlike `STRING{10-5000}` would start from `0010` matching the length of the ending range.
    pub add_preceding_zeros: bool,
}

pub fn args() -> Arguments {
    Arguments::parse()
}
