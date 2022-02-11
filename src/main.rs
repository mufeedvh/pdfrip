#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

mod cli;
mod core;

use crate::cli::interface;
use crate::core::engine;

pub fn main() {
    // print a banner to look cool!
    interface::banner();
    
    let cli = interface::args();

    let wordlist_path: Option<String> = match cli.value_of("wordlist") {
        Some(path) => Some(String::from(path)),
        None => None
    };

    let num_bruteforce: Option<String> = match cli.value_of("num_bruteforce") {
        Some(range) => Some(String::from(range)),
        None => None
    };

    let date_bruteforce: Option<String> = match cli.value_of("date_bruteforce") {
        Some(year) => Some(String::from(year)),
        None => None
    };

    let custom_query: Option<String> = match cli.value_of("custom_query") {
        Some(query) => Some(String::from(query)),
        None => None
    };        

    let pdfrip = engine::PDFRip {
        filepath: String::from(cli.value_of("filename").unwrap()),
        wordlist_path,
        num_bruteforce,
        date_bruteforce,
        custom_query
    };

    pdfrip.crack();
}