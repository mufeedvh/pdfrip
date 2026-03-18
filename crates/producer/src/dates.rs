use std::sync::Arc;

use super::{write_decimal_usize, Producer};

const DATES_PER_YEAR: usize = 12 * 31;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DateFormatToken {
    Day,
    Month,
    Year,
    Literal(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DateFormatTemplate {
    tokens: Vec<DateFormatToken>,
    min_output_len: usize,
}

impl DateFormatTemplate {
    fn parse(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err(String::from("date format must not be empty"));
        }

        let mut tokens = Vec::new();
        let mut min_output_len = 0usize;
        let mut index = 0usize;
        let mut day_count = 0usize;
        let mut month_count = 0usize;
        let mut year_count = 0usize;
        let bytes = pattern.as_bytes();

        while index < bytes.len() {
            let remaining = &pattern[index..];
            if remaining.starts_with("YYYY") {
                tokens.push(DateFormatToken::Year);
                min_output_len += 4;
                year_count += 1;
                index += 4;
                continue;
            }
            if remaining.starts_with("DD") {
                tokens.push(DateFormatToken::Day);
                min_output_len += 2;
                day_count += 1;
                index += 2;
                continue;
            }
            if remaining.starts_with("MM") {
                tokens.push(DateFormatToken::Month);
                min_output_len += 2;
                month_count += 1;
                index += 2;
                continue;
            }

            let ch = remaining
                .chars()
                .next()
                .expect("checked index < bytes.len() above");
            let literal = ch.to_string().into_bytes();
            min_output_len += literal.len();
            tokens.push(DateFormatToken::Literal(literal));
            index += ch.len_utf8();
        }

        if day_count != 1 || month_count != 1 || year_count != 1 {
            return Err(String::from(
                "date format must contain each of DD, MM, and YYYY exactly once",
            ));
        }

        Ok(Self {
            tokens,
            min_output_len,
        })
    }

    fn render_into(&self, day: &[u8], month: &[u8], year: usize, output: &mut Vec<u8>) {
        output.clear();
        output.reserve(self.min_output_len.saturating_sub(output.capacity()));

        for token in &self.tokens {
            match token {
                DateFormatToken::Day => output.extend_from_slice(day),
                DateFormatToken::Month => output.extend_from_slice(month),
                DateFormatToken::Year => write_decimal_usize(output, year, 4),
                DateFormatToken::Literal(literal) => output.extend_from_slice(literal),
            }
        }
    }
}

/// Generates naively valid date passwords across an inclusive year span.
///
/// The producer intentionally mirrors the project's historical `12 * 31` search grid, including
/// calendar-invalid dates, because that is the established search model in this codebase and it
/// keeps the generator finite, deterministic, and exactly countable. A configurable output format
/// makes it possible to cover common real-world password shapes like `DD.MM.YYYY` or
/// `YYYY-MM-DD` without changing the underlying search space.
#[derive(Clone)]
pub struct DateProducer {
    start_year: usize,
    dates: Arc<[[u8; 4]]>,
    format: DateFormatTemplate,
    position: usize,
    size: usize,
}

/// Pregenerates all naively "valid" combinations of days and months.
/// This is probably fine since it's a constant amount anyway.
fn pregenerate_dates() -> Arc<[[u8; 4]]> {
    let mut results = Vec::with_capacity(DATES_PER_YEAR);
    for month in 1..=12 {
        let month_bytes = two_digit_bytes(month);
        for day in 1..=31 {
            let day_bytes = two_digit_bytes(day);
            results.push([day_bytes[0], day_bytes[1], month_bytes[0], month_bytes[1]]);
        }
    }

    Arc::<[[u8; 4]]>::from(results)
}

fn two_digit_bytes(value: usize) -> [u8; 2] {
    [b'0' + (value / 10) as u8, b'0' + (value % 10) as u8]
}

impl DateProducer {
    /// Builds a date producer using the default `DDMMYYYY` output format and panics if the year
    /// range is invalid.
    pub fn new(start: usize, end: usize) -> Self {
        Self::try_new(start, end).expect("date range should be valid")
    }

    /// Validates an inclusive year range and constructs an exact date producer using the default
    /// `DDMMYYYY` format.
    pub fn try_new(start: usize, end: usize) -> Result<Self, String> {
        Self::try_new_with_format(start, end, "DDMMYYYY")
    }

    /// Validates an inclusive year range and a format string built from `DD`, `MM`, and `YYYY`.
    ///
    /// Returns an error if the year span is inverted, the resulting candidate count cannot be
    /// represented exactly in `usize`, or the date format is malformed.
    pub fn try_new_with_format(start: usize, end: usize, format: &str) -> Result<Self, String> {
        if start > end {
            return Err(format!(
                "invalid year range {start}-{end}; start year must not exceed end year"
            ));
        }

        let years = end
            .checked_sub(start)
            .and_then(|delta| delta.checked_add(1))
            .ok_or_else(|| String::from("date range is too large to count exactly"))?;
        let size = DATES_PER_YEAR
            .checked_mul(years)
            .ok_or_else(|| String::from("date range is too large to count exactly"))?;

        Ok(Self {
            start_year: start,
            dates: pregenerate_dates(),
            format: DateFormatTemplate::parse(format)?,
            position: 0,
            size,
        })
    }
}

impl Producer for DateProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.position >= self.size {
            debug!("event=date_producer_exhausted position={}", self.position);
            return Ok(None);
        }

        let mut password = Vec::new();
        let produced = self.next_into(&mut password)?;
        debug_assert!(produced, "position checked before calling next_into");
        Ok(Some(password))
    }

    fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        if self.position >= self.size {
            debug!("event=date_producer_exhausted position={}", self.position);
            output.clear();
            return Ok(false);
        }

        let date_index = self.position % self.dates.len();
        let year_offset = self.position / self.dates.len();
        let year = self
            .start_year
            .checked_add(year_offset)
            .ok_or_else(|| String::from("date range overflowed while generating candidates"))?;
        self.position += 1;

        let raw_date = &self.dates[date_index];
        let day = &raw_date[0..2];
        let month = &raw_date[2..4];
        self.format.render_into(day, month, year, output);
        debug!(
            "event=date_producer_emit candidate={} position={}",
            String::from_utf8_lossy(output),
            self.position
        );

        Ok(true)
    }

    fn size(&self) -> usize {
        self.size
    }

    fn skip(&mut self, count: usize) -> Result<usize, String> {
        let remaining = self.size.saturating_sub(self.position);
        let skipped = count.min(remaining);
        self.position += skipped;
        Ok(skipped)
    }

    fn boxed_clone(&self) -> Option<Box<dyn Producer>> {
        Some(Box::new(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use crate::Producer;

    use super::{DateFormatTemplate, DateProducer, DATES_PER_YEAR};

    fn drain(mut producer: DateProducer) -> Vec<Vec<u8>> {
        let mut values = Vec::new();

        while let Some(value) = producer.next().expect("date producer should not error") {
            values.push(value);
        }

        values
    }

    fn drain_into(producer: &mut dyn Producer) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let mut candidate = Vec::new();

        while producer.next_into(&mut candidate).unwrap() {
            values.push(candidate.clone());
        }

        values
    }

    #[test]
    fn instantiate_instance() {
        let _ = DateProducer::new(1337, 1338);
    }

    #[test]
    fn test_size_is_correct_for_inclusive_year_ranges() {
        let producer = DateProducer::new(1337, 1338);
        let size = producer.size();
        let passwords = drain(producer);

        assert_eq!(size, DATES_PER_YEAR * 2);
        assert_eq!(size, passwords.len())
    }

    #[test]
    fn can_run_exactly_one_year() {
        let producer = DateProducer::new(1337, 1337);
        let passwords = drain(producer);

        assert_eq!(passwords.len(), DATES_PER_YEAR);
        assert_eq!(passwords.first().cloned(), Some(b"01011337".to_vec()));
        assert_eq!(passwords.last().cloned(), Some(b"31121337".to_vec()));
    }

    #[test]
    fn supports_custom_output_formats() {
        let mut producer = DateProducer::try_new_with_format(2000, 2000, "DD.MM.YYYY")
            .expect("custom date format should be valid");

        assert_eq!(producer.next().unwrap(), Some(b"01.01.2000".to_vec()));
    }

    #[test]
    fn rejects_inverted_year_ranges() {
        assert!(DateProducer::try_new(2001, 2000).is_err());
    }

    #[test]
    fn rejects_invalid_format_tokens() {
        assert!(DateFormatTemplate::parse("MMYYYY").is_err());
        assert!(DateFormatTemplate::parse("DDMMYY").is_err());
    }

    #[test]
    fn skip_jumps_directly_to_the_requested_date() {
        let mut producer = DateProducer::new(2000, 2000);

        assert_eq!(producer.skip(2).unwrap(), 2);
        assert_eq!(producer.next().unwrap(), Some(b"03012000".to_vec()));
    }

    #[test]
    fn next_into_matches_date_iteration_order() {
        let expected = drain(DateProducer::try_new_with_format(1999, 2000, "YYYY-MM-DD").unwrap());
        let mut producer = DateProducer::try_new_with_format(1999, 2000, "YYYY-MM-DD").unwrap();

        assert_eq!(drain_into(&mut producer), expected);
    }
}
