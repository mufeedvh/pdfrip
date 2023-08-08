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
        filepath: cli.filename,
        wordlist_path: cli.wordlist,
        num_bruteforce: cli.num_bruteforce,
        date_bruteforce: cli.date_bruteforce,
        custom_query: cli.custom_query,
        preceding_zeros_enabled: cli.add_preceding_zeros,
    };

    pdfrip.crack()
}
