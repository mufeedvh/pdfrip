#[cfg(not(windows))]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

#[macro_use]
extern crate log;

mod cli;
mod core;

use env_logger::Env;

use crate::cli::interface;
use crate::core::engine;

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("INFO")).init();
    // print a banner to look cool!
    interface::banner();
    let cli = interface::args();

    let pdfrip = engine::PDFRip {
        filepath: cli.filename,
        wordlist_path: cli.wordlist,
        num_bruteforce: cli.num_bruteforce,
        preceding_zeros_enabled: cli.add_preceding_zeros,
    };

    match pdfrip.crack() {
        Ok(_) => {},
        Err(err) => error!("An error occured {}", err),
    }
}
