use super::Producer;

/// Per-length metadata used to map a global brute-force offset back to a concrete candidate.
#[derive(Clone)]
struct LengthSearchSpace {
    len: usize,
    candidates: usize,
}

/// Generates brute-force candidates across a fixed printable ASCII charset.
///
/// The generator enumerates every candidate from `min_length` through `max_length` exactly once
/// and reports a count that matches the emitted search space. This matters because the engine now
/// uses the producer for exact progress accounting and checkpoint resume, both of which require a
/// stable mapping from candidate index to emitted password.
#[derive(Clone)]
pub struct DefaultQuery {
    size: usize,
    position: usize,
    char_set: std::sync::Arc<[u8]>,
    length_spaces: Vec<LengthSearchSpace>,
}

impl DefaultQuery {
    /// Builds a default-query generator and panics if the configuration is invalid.
    ///
    /// This constructor is kept for compatibility with existing internal call sites. New
    /// user-facing paths should prefer [`DefaultQuery::try_new`] so invalid bounds can be reported
    /// as normal CLI errors instead of panics.
    pub fn new(max_length: u32, min_length: u32) -> Self {
        Self::try_new(max_length, min_length).expect("default-query configuration should be valid")
    }

    /// Validates the requested length span and constructs an exact brute-force iterator.
    ///
    /// The generated charset includes printable ASCII characters, including the space character,
    /// so search spaces involving punctuation and whitespace remain reachable. Returns an error if
    /// the bounds are inverted or if the search space is too large to count exactly in `usize`.
    pub fn try_new(max_length: u32, min_length: u32) -> Result<Self, String> {
        if min_length > max_length {
            return Err(format!(
                "minimum length ({min_length}) must not exceed maximum length ({max_length})"
            ));
        }

        let char_set = Self::default_char_set();
        let length_spaces =
            Self::build_length_spaces(char_set.len(), min_length as usize, max_length as usize)?;
        let size = length_spaces.iter().try_fold(0usize, |total, space| {
            total.checked_add(space.candidates).ok_or_else(|| {
                String::from("default-query search space is too large to count exactly")
            })
        })?;

        Ok(Self {
            size,
            position: 0,
            char_set,
            length_spaces,
        })
    }

    fn default_char_set() -> std::sync::Arc<[u8]> {
        let mut char_set: Vec<u8> = std::iter::once(b' ')
            .chain(b'0'..=b'9')
            .chain(b'A'..=b'Z')
            .chain(b'a'..=b'z')
            .chain(b'!'..=b'/')
            .chain(b':'..=b'@')
            .chain(b'['..=b'`')
            .chain(b'{'..=b'~')
            .collect();

        char_set.sort();
        std::sync::Arc::<[u8]>::from(char_set)
    }

    fn build_length_spaces(
        radix: usize,
        min_length: usize,
        max_length: usize,
    ) -> Result<Vec<LengthSearchSpace>, String> {
        let mut length_spaces = Vec::with_capacity(max_length.saturating_sub(min_length) + 1);

        for len in min_length..=max_length {
            let candidates = radix.checked_pow(len as u32).ok_or_else(|| {
                format!("default-query search space is too large to count exactly for length {len}")
            })?;
            length_spaces.push(LengthSearchSpace { len, candidates });
        }

        Ok(length_spaces)
    }

    fn candidate_for_offset_into(
        &self,
        mut offset: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), String> {
        let radix = self.char_set.len();

        for length_space in &self.length_spaces {
            if offset >= length_space.candidates {
                offset -= length_space.candidates;
                continue;
            }

            output.clear();
            output.resize(length_space.len, 0);

            let mut value = offset;
            for byte in output.iter_mut() {
                *byte = self.char_set[value % radix];
                value /= radix;
            }
            return Ok(());
        }

        Err(String::from(
            "default-query offset exceeded the available search space",
        ))
    }
}

impl Producer for DefaultQuery {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.position >= self.size {
            return Ok(None);
        }

        let mut candidate = Vec::new();
        self.candidate_for_offset_into(self.position, &mut candidate)?;
        self.position += 1;
        Ok(Some(candidate))
    }

    fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        if self.position >= self.size {
            output.clear();
            return Ok(false);
        }

        self.candidate_for_offset_into(self.position, output)?;
        self.position += 1;
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
    use std::collections::HashSet;

    use crate::Producer;

    use super::DefaultQuery;

    fn drain(mut producer: DefaultQuery) -> Vec<Vec<u8>> {
        let mut values = Vec::new();

        while let Some(value) = producer.next().expect("default-query should not error") {
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
    fn includes_the_initial_candidate_and_terminates_cleanly() {
        let mut producer = DefaultQuery::new(1, 1);
        let mut values = Vec::new();

        while let Some(value) = producer.next().expect("default-query should not error") {
            values.push(String::from_utf8(value).expect("character set should stay utf-8"));
        }

        assert_eq!(values.first().map(String::as_str), Some(" "));
        assert_eq!(values.last().map(String::as_str), Some("~"));
        assert_eq!(values.len(), 95);
        assert!(producer
            .next()
            .expect("default-query should stay finished")
            .is_none());
    }

    #[test]
    fn size_matches_every_emitted_candidate() {
        let producer = DefaultQuery::new(2, 1);
        let expected_size = producer.size();
        let values = drain(producer);
        let unique = values.iter().cloned().collect::<HashSet<Vec<u8>>>();

        assert_eq!(values.len(), expected_size);
        assert_eq!(unique.len(), expected_size);
    }

    #[test]
    fn rejects_inverted_lengths() {
        let error = match DefaultQuery::try_new(3, 4) {
            Ok(_) => panic!("invalid lengths should fail"),
            Err(error) => error,
        };
        assert!(error.contains("minimum length"));
    }

    #[test]
    fn skip_advances_to_the_expected_ascii_candidate() {
        let mut producer = DefaultQuery::new(2, 1);

        assert_eq!(producer.skip(95).unwrap(), 95);
        assert_eq!(producer.next().unwrap(), Some(b"  ".to_vec()));
    }

    #[test]
    fn next_into_matches_default_query_iteration_order() {
        let expected = drain(DefaultQuery::new(2, 1));
        let mut producer = DefaultQuery::new(2, 1);

        assert_eq!(drain_into(&mut producer), expected);
    }
}
