/// This crate exists to separate our main binary from it's CLI interface.
use anyhow::Context;
use arguments::{Arguments, Method};
use engine::{
    crackers::PDFCracker,
    producers::{
        custom_query::CustomQuery, dates::DateProducer, default_query::DefaultQuery,
        dictionary::LineProducer, number_ranges::RangeProducer, Producer,
    },
};
use log::info;

/// Contains the Argument parser
pub mod arguments;

mod banner;

// Used to ascertain if we succeeded or not
pub enum Code {
    Success,
    Failure,
}

// Re-export our Result type instead of defining our own since I'm lazy..
pub type Result = anyhow::Result<Code>;

fn select_producer(subcommand: Method) -> Box<dyn Producer> {
    match subcommand {
        Method::Wordlist(args) => {
            let producer = LineProducer::from(&args.wordlist);
            Box::from(producer)
        }
        Method::Range(args) => {
            let padding: usize = if args.add_preceding_zeros {
                args.upper_bound.checked_ilog10().unwrap() as usize + 1
            } else {
                0
            };
            let producer = RangeProducer::new(padding, args.lower_bound, args.upper_bound);
            Box::from(producer)
        }
        Method::CustomQuery(args) => {
            let producer = CustomQuery::new(&args.custom_query, args.add_preceding_zeros);
            Box::from(producer)
        }
        Method::Date(args) => {
            let producer = DateProducer::new(args.start, args.end);
            Box::from(producer)
        }
        Method::DefaultQuery(args) => {
            let producer = DefaultQuery::new(args.max_length, args.min_length);
            Box::from(producer)
        }
    }
}

pub fn entrypoint(args: Arguments) -> Result {
    // Print our cool banner!
    banner::banner();
    let producer: Box<dyn Producer> = select_producer(args.subcommand);

    let filename = args.filename;

    let res = engine::crack_file(
        args.number_of_threads,
        PDFCracker::from_file(&filename).context(format!("path: {}", filename))?,
        producer,
    )?;

    match res {
        Some(password) => match std::str::from_utf8(&password) {
            Ok(password) => {
                info!("Success! Found password: {}", password)
            }
            Err(_) => {
                let hex_string: String = password
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<String>>()
                    .join(" ");
                info!(
                            "Success! Found password, but it contains invalid UTF-8 characters. Displaying as hex: {}",
                            hex_string
                        )
            }
        },
        None => {
            info!("Failed to crack file...");
            return Ok(Code::Failure);
        }
    }

    Ok(Code::Success)
}
