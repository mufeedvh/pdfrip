#[macro_use]
extern crate log;

pub trait Producer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String>;
    /// Used for measuring progress. Reflects the number of passwords this producer can produce
    fn size(&self) -> usize;
}

/// Producers that handle dictionary-style attacks
pub mod dictionary;

/// Producers that handle number-range attack
pub mod number_ranges;

/// Parses a custom query and generates passwords accordingly
pub mod custom_query;

/// handles creating passwords matching dates in DDMMYYYY format
pub mod dates;

/// Does a traditional brute-force search through all possible combinations
/// of letters and numbers
pub mod default_query;
