#[cfg(not(windows))]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

#[macro_use]
extern crate log;

mod cli;
mod core;

use std::path::Path;

use env_logger::Env;

use crate::cli::interface;
use crate::core::engine;

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("INFO")).init();
    // print a banner to look cool!
    interface::banner();
    let cli = interface::args();

    let padding: usize = cli.upper_bound.checked_ilog10().unwrap() as usize + 1;

    let producer = core::production::number_ranges::RangeProducer::new(
        padding,
        cli.lower_bound,
        cli.upper_bound,
    );
    engine::v1::crack_file(&Path::new(&cli.filename), 100, Box::from(producer)).unwrap();
}
