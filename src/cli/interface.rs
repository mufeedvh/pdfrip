use clap::{ArgGroup, Parser};
use colored::*;

pub fn banner() {
    eprintln!("{}", include_str!("banner").bold().red())
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(group(ArgGroup::new("actions").required(true).args(&["wordlist", "num-bruteforce",])))]
#[clap(group(ArgGroup::new("ranges").args(&["lower-bound", "upper-bound"]).requires("num-bruteforce").multiple(true)))]
/// A fast PDF password cracking utility written in Rust.
pub struct Arguments {
    #[clap(short, long, default_value_t = 4)]
    /// Number of worker threads
    pub number_of_threads: usize,

    #[clap(short, long)]
    /// The filename of the PDF
    pub filename: String,

    #[clap(long)]
    /// Path to the pasword wordlist.
    pub wordlist: Option<String>,

    #[clap(long)]
    /// Bruteforce numbers for the password with the given range.
    pub num_bruteforce: bool,

    pub lower_bound: usize,
    pub upper_bound: usize,

    #[clap(short, long)]
    /// Enabling this adds preceding zeros to number ranges in custom queries.\n\nlike `STRING{10-5000}` would start from `0010` matching the length of the ending range.
    pub add_preceding_zeros: bool,
}

pub fn args() -> Arguments {
    Arguments::parse()
}
