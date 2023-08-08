#[macro_use]
extern crate log;

mod cli;
mod core;

use crate::core::production::Producer;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;

use crate::cli::interface;
use crate::core::{engine, production};

pub fn main() {
    pretty_env_logger::formatted_timed_builder()
        .parse_env("LOG_LEVEL")
        .init();
    // print a banner to look cool!
    interface::banner();
    let cli = interface::args();

    let padding: usize = cli.upper_bound.checked_ilog10().unwrap() as usize + 1;

    let producer: Box<dyn Producer> = if cli.num_bruteforce {
        let producer = production::number_ranges::RangeProducer::new(
            padding,
            cli.lower_bound,
            cli.upper_bound,
        );

        Box::from(producer)
    } else if let Some(path) = cli.wordlist {
        let lines = fs::read(&path)
            .unwrap()
            .iter()
            .filter(|x| {
                if let Some(y) = char::from_u32(**x as u32) {
                    y == '\n'
                } else {
                    false
                }
            })
            .count();
        let file = File::open(path).unwrap();

        let producer =
            production::dictionary::LineProducer::new(Box::from(BufReader::new(file)), lines);
        Box::from(producer)
    } else {
        return;
    };

    engine::crack_file(&Path::new(&cli.filename), cli.number_of_threads, producer).unwrap();
}
