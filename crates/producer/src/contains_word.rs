use std::{fs, sync::Arc};

use super::Producer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillCharset {
    Ascii,
    Lower,
    Upper,
    Digit,
    Special,
}

impl FillCharset {
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name {
            "ascii" => Ok(Self::Ascii),
            "lower" => Ok(Self::Lower),
            "upper" => Ok(Self::Upper),
            "digit" => Ok(Self::Digit),
            "special" => Ok(Self::Special),
            _ => Err(format!(
                "unsupported fill charset '{name}'; expected one of ascii, lower, upper, digit, special"
            )),
        }
    }

    pub fn bytes(self) -> Vec<u8> {
        match self {
            Self::Ascii => std::iter::once(b' ').chain(b'!'..=b'~').collect(),
            Self::Lower => (b'a'..=b'z').collect(),
            Self::Upper => (b'A'..=b'Z').collect(),
            Self::Digit => (b'0'..=b'9').collect(),
            Self::Special => std::iter::once(b' ')
                .chain(b'!'..=b'/')
                .chain(b':'..=b'@')
                .chain(b'['..=b'`')
                .chain(b'{'..=b'~')
                .collect(),
        }
    }
}

/// Generates candidates that must contain one of a supplied set of words.
///
/// For each word, the producer tries every total length between `min_length` and `max_length`,
/// every insertion position for that word, and every combination of the selected filler charset in
/// the remaining slots. The resulting search space is deterministic, finite, exactly countable,
/// and suitable for checkpoint/resume.
#[derive(Clone)]
pub struct ContainsWordProducer {
    words: Arc<Vec<Vec<u8>>>,
    min_length: usize,
    max_length: usize,
    charset: Arc<[u8]>,
    size: usize,
    position: usize,
}

impl ContainsWordProducer {
    pub fn new(
        path: &str,
        min_length: usize,
        max_length: usize,
        fill_charset: FillCharset,
    ) -> Self {
        Self::try_new(path, min_length, max_length, fill_charset)
            .expect("contains-word configuration should be valid")
    }

    pub fn try_new(
        path: &str,
        min_length: usize,
        max_length: usize,
        fill_charset: FillCharset,
    ) -> Result<Self, String> {
        if min_length > max_length {
            return Err(format!(
                "minimum length ({min_length}) must not exceed maximum length ({max_length})"
            ));
        }

        let bytes = fs::read(path)
            .map_err(|err| format!("Unable to read wordlist file '{path}': {err}"))?;
        let words = Arc::new(parse_words(&bytes));
        if words.is_empty() {
            return Err(String::from(
                "contains-word requires at least one non-empty word in the supplied file",
            ));
        }

        let charset = Arc::<[u8]>::from(fill_charset.bytes());
        let mut size = 0usize;
        for word in words.iter() {
            let word_size =
                candidate_count_for_word(word.len(), min_length, max_length, charset.len())?;
            size = size.checked_add(word_size).ok_or_else(|| {
                String::from("contains-word search space is too large to count exactly")
            })?;
        }

        Ok(Self {
            words,
            min_length,
            max_length,
            charset,
            size,
            position: 0,
        })
    }

    fn render_candidate_into(
        &self,
        word: &[u8],
        total_length: usize,
        insert_pos: usize,
        mut filler_index: usize,
        output: &mut Vec<u8>,
    ) {
        let word_end = insert_pos + word.len();
        let radix = self.charset.len();

        output.clear();
        output.reserve(total_length.saturating_sub(output.capacity()));

        for position in 0..total_length {
            if position == insert_pos {
                output.extend_from_slice(word);
            }
            if position < insert_pos || position >= word_end {
                output.push(self.charset[filler_index % radix]);
                filler_index /= radix;
            }
        }
    }
}

impl Producer for ContainsWordProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.position >= self.size {
            return Ok(None);
        }

        let mut candidate = Vec::new();
        let produced = self.next_into(&mut candidate)?;
        debug_assert!(produced, "position checked before calling next_into");
        Ok(Some(candidate))
    }

    fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        if self.position >= self.size {
            output.clear();
            return Ok(false);
        }

        let mut offset = self.position;
        let radix = self.charset.len();

        for word in self.words.iter() {
            let word_size =
                candidate_count_for_word(word.len(), self.min_length, self.max_length, radix)?;
            if offset >= word_size {
                offset -= word_size;
                continue;
            }

            for total_length in self.min_length.max(word.len())..=self.max_length {
                let filler_slots = total_length - word.len();
                let fillers_per_position =
                    radix.checked_pow(filler_slots as u32).ok_or_else(|| {
                        String::from("contains-word filler space is too large to count exactly")
                    })?;
                let positions = filler_slots + 1;
                let local_count = positions
                    .checked_mul(fillers_per_position)
                    .ok_or_else(|| String::from("contains-word position count overflowed"))?;
                if offset >= local_count {
                    offset -= local_count;
                    continue;
                }

                let insert_pos = offset / fillers_per_position;
                let filler_index = offset % fillers_per_position;
                self.render_candidate_into(word, total_length, insert_pos, filler_index, output);
                self.position += 1;
                return Ok(true);
            }
        }

        Err(String::from(
            "contains-word offset exceeded the available search space",
        ))
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

fn parse_words(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut words = Vec::new();
    let mut start = 0usize;

    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }

        let mut end = index;
        if end > start && bytes[end - 1] == b'\r' {
            end -= 1;
        }
        if start < end {
            words.push(bytes[start..end].to_vec());
        }
        start = index + 1;
    }

    if start < bytes.len() {
        let mut end = bytes.len();
        if end > start && bytes[end - 1] == b'\r' {
            end -= 1;
        }
        if start < end {
            words.push(bytes[start..end].to_vec());
        }
    }

    words
}

fn candidate_count_for_word(
    word_length: usize,
    min_length: usize,
    max_length: usize,
    radix: usize,
) -> Result<usize, String> {
    let mut total = 0usize;

    for total_length in min_length.max(word_length)..=max_length {
        let filler_slots = total_length - word_length;
        let fillers_per_position = radix.checked_pow(filler_slots as u32).ok_or_else(|| {
            String::from("contains-word filler space is too large to count exactly")
        })?;
        let positions = filler_slots + 1;
        total = total
            .checked_add(
                positions
                    .checked_mul(fillers_per_position)
                    .ok_or_else(|| String::from("contains-word position count overflowed"))?,
            )
            .ok_or_else(|| {
                String::from("contains-word search space is too large to count exactly")
            })?;
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::Producer;

    use super::{ContainsWordProducer, FillCharset};

    fn temp_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("pdfrip-{name}-{}-{unique}.txt", std::process::id()))
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
    fn generates_candidates_that_embed_the_word() {
        let path = temp_path("contains-word");
        std::fs::write(&path, b"ALICE\n").expect("wordlist should be writable");

        let mut producer = ContainsWordProducer::try_new(
            path.to_str().expect("path should be utf-8"),
            5,
            6,
            FillCharset::Digit,
        )
        .expect("producer should build");

        assert_eq!(producer.next().unwrap(), Some(b"ALICE".to_vec()));
        assert_eq!(producer.next().unwrap(), Some(b"ALICE0".to_vec()));
        assert_eq!(producer.skip(9).unwrap(), 9);
        assert_eq!(producer.next().unwrap(), Some(b"0ALICE".to_vec()));

        std::fs::remove_file(&path).expect("temporary wordlist should be removable");
    }

    #[test]
    fn rejects_empty_wordlists() {
        let path = temp_path("contains-word-empty");
        std::fs::write(&path, b"\n\r\n").expect("wordlist should be writable");

        assert!(ContainsWordProducer::try_new(
            path.to_str().expect("path should be utf-8"),
            1,
            2,
            FillCharset::Ascii,
        )
        .is_err());

        std::fs::remove_file(&path).expect("temporary wordlist should be removable");
    }

    #[test]
    fn next_into_matches_contains_word_iteration_order() {
        let path = temp_path("contains-word-next-into");
        std::fs::write(&path, b"ALICE\nBOB\n").expect("wordlist should be writable");

        let expected = {
            let mut producer = ContainsWordProducer::try_new(
                path.to_str().expect("path should be utf-8"),
                3,
                6,
                FillCharset::Digit,
            )
            .expect("producer should build");
            let mut values = Vec::new();
            while let Some(value) = producer.next().unwrap() {
                values.push(value);
            }
            values
        };

        let mut producer = ContainsWordProducer::try_new(
            path.to_str().expect("path should be utf-8"),
            3,
            6,
            FillCharset::Digit,
        )
        .expect("producer should build");
        assert_eq!(drain_into(&mut producer), expected);

        std::fs::remove_file(&path).expect("temporary wordlist should be removable");
    }
}
