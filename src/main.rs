#[macro_use]
extern crate log;

mod cli;
mod core;

use anyhow::{bail, Context};
use pretty_env_logger::env_logger::Env;

use crate::core::cracker::pdf::PDFCracker;
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

    let padding: usize = cli.upper_bound.checked_ilog10().unwrap() as usize + 1;

    let producer: Box<dyn Producer> = if cli.num_bruteforce {
        let producer = production::number_ranges::RangeProducer::new(
            padding,
            cli.lower_bound,
            cli.upper_bound,
        );
        Box::from(producer)
    } else if let Some(path) = cli.wordlist {
        let producer = LineProducer::from(&path);
        Box::from(producer)
    } else {
        bail!("No supported arguments found, contact the developers since this means the argument parser is not working properly");
    };

    let cracker =
        PDFCracker::from_file(&cli.filename).context(format!("path: {}", cli.filename))?;

    engine::crack_file(cli.number_of_threads, Box::new(cracker), producer)?;

    Ok(())
}
