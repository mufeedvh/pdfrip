#[cfg(not(windows))]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

mod cli;
mod core;

use crate::cli::interface;
use crate::core::engine;

pub fn main() -> std::io::Result<()> {
    // print a banner to look cool!
    interface::banner();
    
    let cli = interface::args();

    let pdfrip = engine::PDFRip {
        filepath: String::from(cli.value_of("filename").unwrap()),
        wordlist_path: cli.value_of("wordlist").map(|s| String::from(s)),
        num_bruteforce: cli.value_of("num_bruteforce").map(|s| String::from(s)),
        date_bruteforce: cli.value_of("date_bruteforce").map(|s| String::from(s)),
        custom_query: cli.value_of("custom_query").map(|s| String::from(s))
    };

    pdfrip.crack()
}
