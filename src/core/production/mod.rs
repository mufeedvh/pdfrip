pub trait Producer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String>;
    /// Used for measuring progress. Reflects the number of passwords this producer can produce
    fn size(&self) -> usize;

    /// Returns an error message if one occurred during processing.
    fn error_msg(&self) ->Option<String> { None }
}

/// Producers that handle dictionary-style attacks
pub mod dictionary;

/// Producers that handle number-range attack
pub mod number_ranges;

/// Parses a custom query and generates passwords accordingly
pub mod custom_query;

/// handles creating passwords matching dates in DDMMYYYY format
pub mod dates;
