use super::{write_decimal_usize, Producer};

/// Generates passwords from an inclusive numeric range.
///
/// Inclusive semantics match how users typically describe brute-force number spans and ensure the
/// reported candidate count matches the values actually emitted. The implementation keeps an exact
/// positional cursor so checkpoint resume can jump straight to the requested offset.
#[derive(Clone)]
pub struct RangeProducer {
    padding_len: usize,
    lower_bound: usize,
    size: usize,
    position: usize,
}

impl RangeProducer {
    /// Builds an inclusive numeric-range producer and panics on invalid bounds.
    ///
    /// This compatibility constructor is fine for internal callers that already know their bounds
    /// are valid. User-facing paths should prefer [`RangeProducer::try_new`] so inverted bounds
    /// become regular errors.
    pub fn new(padding_len: usize, lower_bound: usize, upper_bound: usize) -> Self {
        Self::try_new(padding_len, lower_bound, upper_bound).expect("number range should be valid")
    }

    /// Validates inclusive numeric bounds and constructs a countable range producer.
    ///
    /// Returns an error if the lower bound exceeds the upper bound or if the candidate count cannot
    /// be represented exactly in `usize`.
    pub fn try_new(
        padding_len: usize,
        lower_bound: usize,
        upper_bound: usize,
    ) -> Result<Self, String> {
        if lower_bound > upper_bound {
            return Err(format!(
                "invalid number range {lower_bound}-{upper_bound}; lower bound must not exceed upper bound"
            ));
        }

        let size = upper_bound
            .checked_sub(lower_bound)
            .and_then(|delta| delta.checked_add(1))
            .ok_or_else(|| String::from("number range is too large to count exactly"))?;

        Ok(Self {
            padding_len,
            lower_bound,
            size,
            position: 0,
        })
    }
}

impl RangeProducer {
    fn next_number(&mut self) -> Result<Option<usize>, String> {
        if self.position >= self.size {
            return Ok(None);
        }

        let number = self
            .lower_bound
            .checked_add(self.position)
            .ok_or_else(|| String::from("number range overflowed while generating candidates"))?;
        self.position += 1;
        Ok(Some(number))
    }
}

impl Producer for RangeProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let Some(number) = self.next_number()? else {
            return Ok(None);
        };

        let mut output = Vec::new();
        write_decimal_usize(&mut output, number, self.padding_len);
        Ok(Some(output))
    }

    fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        let Some(number) = self.next_number()? else {
            output.clear();
            return Ok(false);
        };

        output.clear();
        write_decimal_usize(output, number, self.padding_len);
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

    use super::RangeProducer;

    fn drain_into(producer: &mut dyn Producer) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let mut candidate = Vec::new();

        while producer.next_into(&mut candidate).unwrap() {
            values.push(candidate.clone());
        }

        values
    }

    #[test]
    fn range_bounds_are_inclusive() {
        let mut producer = RangeProducer::new(0, 7, 9);
        let mut values = Vec::new();

        while let Some(value) = producer.next().expect("range should not error") {
            values.push(String::from_utf8(value).expect("range should stay utf-8"));
        }

        assert_eq!(producer.size(), 3);
        assert_eq!(values, vec!["7", "8", "9"]);
        assert_eq!(producer.next().unwrap(), None);
    }

    #[test]
    fn rejects_inverted_ranges() {
        assert!(RangeProducer::try_new(0, 10, 9).is_err());
    }

    #[test]
    fn skip_jumps_to_the_requested_bound() {
        let mut producer = RangeProducer::new(0, 7, 9);

        assert_eq!(producer.skip(1).unwrap(), 1);
        assert_eq!(producer.next().unwrap(), Some(b"8".to_vec()));
    }

    #[test]
    fn next_into_matches_number_range_iteration_order() {
        let expected = {
            let mut producer = RangeProducer::new(4, 7, 10);
            let mut values = Vec::new();
            while let Some(value) = producer.next().unwrap() {
                values.push(value);
            }
            values
        };

        let mut producer = RangeProducer::new(4, 7, 10);
        assert_eq!(drain_into(&mut producer), expected);
    }
}
