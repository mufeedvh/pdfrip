#[macro_use]
extern crate log;

mod cli;
mod core;

use crate::core::production::dates::DateProducer;

use anyhow::Context;
use pretty_env_logger::env_logger::Env;

use crate::core::cracker::pdf::PDFCracker;
use crate::core::production::custom_query::CustomQuery;
use crate::core::production::dictionary::LineProducer;
use crate::core::production::Producer;

use crate::cli::interface;
use crate::core::{engine, production};

pub fn main() -> anyhow::Result<()> {
    let env = Env::default().filter_or("LOG_LEVEL", "info");
    pretty_env_logger::formatted_timed_builder()
        .parse_env(env)
        .init();
    // print a banner to look cool!
    interface::banner();
    let cli = interface::args();
    let cracker =
        PDFCracker::from_file(&cli.filename).context(format!("path: {}", cli.filename))?;

    let producer: Box<dyn Producer> = match cli.subcommand {
        interface::Method::Wordlist(args) => {
            let producer = LineProducer::from(&args.wordlist);
            Box::from(producer)
        }
        interface::Method::Range(args) => {
            let padding: usize = if args.add_preceding_zeros {
                args.upper_bound.checked_ilog10().unwrap() as usize + 1
            } else {
                0
            };
            let producer = production::number_ranges::RangeProducer::new(
                padding,
                args.lower_bound,
                args.upper_bound,
            );
            Box::from(producer)
        }
        interface::Method::CustomQuery(args) => {
            let producer = CustomQuery::new(&args.custom_query, args.add_preceding_zeros);
            Box::from(producer)
        }
        interface::Method::Date(args) => {
            let producer = DateProducer::new(args.year);
            Box::from(producer)
        }
    };

    engine::crack_file(cli.number_of_threads, Box::new(cracker), producer)?;

    Ok(())
}
