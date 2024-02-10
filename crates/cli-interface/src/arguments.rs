use clap::{Args, Parser, Subcommand};

#[derive(Args, Debug, Clone)]
pub struct DictionaryArgs {
    #[clap(required = true)]
    /// Path to the password wordlist.
    pub wordlist: String,
}

#[derive(Args, Debug, Clone)]
pub struct RangeArgs {
    #[clap(short, long)]
    /// Enabling this adds preceding zeros to number ranges matching the upper bound length.
    pub add_preceding_zeros: bool,
    pub lower_bound: usize,
    pub upper_bound: usize,
}

#[derive(Args, Debug, Clone)]
pub struct CustomQueryArgs {
    /// Start a bruteforce attack with a custom formatted query and a number range like `-q STRING{1000-3000}`
    pub custom_query: String,

    #[clap(short, long)]
    /// Enabling this adds preceding zeros to number ranges in custom queries.\n\nlike `STRING{10-5000}` would start from `0010` matching the length of the ending range.
    pub add_preceding_zeros: bool,
}

#[derive(Args, Debug, Clone)]
pub struct DefaultQueryArgs {
    #[clap(long, default_value_t = 4)]
    pub min_length: u32,

    #[clap(long)]
    pub max_length: u32,
}

#[derive(Args, Debug, Clone)]
/// Enumerate a span of years, testing passwords in DDMMYYYY format
pub struct DateArgs {
    /// Starting year in format YYYY, inclusive
    pub start: usize,
    /// Final year in format YYYY, inclusive.
    pub end: usize,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Method {
    Wordlist(DictionaryArgs),
    Range(RangeArgs),
    CustomQuery(CustomQueryArgs),
    Date(DateArgs),
    DefaultQuery(DefaultQueryArgs),
}

// Let's use Clap to ensure our program can only be called with valid parameter combinations
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// A fast PDF password cracking utility written in Rust.
pub struct Arguments {
    #[clap(short, long, default_value_t = 4)]
    /// Number of worker threads
    pub number_of_threads: usize,

    #[clap(short, long)]
    /// The filename of the PDF
    pub filename: String,

    #[command(subcommand)]
    /// Bruteforcing method
    pub subcommand: Method,
}

pub fn args() -> Arguments {
    Arguments::parse()
}
