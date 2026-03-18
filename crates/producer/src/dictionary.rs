use std::{fs, sync::Arc};

use super::Producer;

/// Streams password candidates from a wordlist, one line at a time.
///
/// The producer loads the file into memory once, indexes every line boundary, and then serves
/// slices from that immutable buffer. This keeps progress accounting exact, makes resume skips
/// effectively O(1), and normalizes common Unix/Windows line-ending differences without
/// reopening the file. Empty lines are preserved as empty-password candidates so blank-password
/// workflows stay possible in both human and automated runs.
#[derive(Clone)]
pub struct LineProducer {
    bytes: Arc<[u8]>,
    lines: Arc<[(usize, usize)]>,
    position: usize,
}

impl LineProducer {
    /// Builds a line-based producer and panics if the path cannot be read.
    ///
    /// This constructor is retained for compatibility with existing internal call sites. User
    /// facing paths should prefer [`LineProducer::try_from_path`] so missing files surface as
    /// normal CLI errors instead of panics.
    pub fn from(path: &str) -> Self {
        Self::try_from_path(path).expect("wordlist path should be readable")
    }

    /// Loads a wordlist from disk and constructs a CRLF-safe line producer.
    ///
    /// The file is read into memory once so the implementation can both count candidates exactly
    /// and skip to a resume offset without reparsing previously consumed lines.
    pub fn try_from_path(path: &str) -> Result<Self, String> {
        let bytes = Arc::<[u8]>::from(
            fs::read(path)
                .map_err(|err| format!("Unable to read wordlist file '{path}': {err}"))?,
        );
        let lines = Arc::<[(usize, usize)]>::from(Self::index_lines(&bytes));

        Ok(Self {
            bytes,
            lines,
            position: 0,
        })
    }

    fn index_lines(bytes: &[u8]) -> Vec<(usize, usize)> {
        if bytes.is_empty() {
            return Vec::new();
        }

        let mut lines = Vec::with_capacity(bytecount::count(bytes, b'\n') + 1);
        let mut start = 0usize;

        for (index, byte) in bytes.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }

            let mut end = index;
            if end > start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            lines.push((start, end));
            start = index + 1;
        }

        if start < bytes.len() {
            let mut end = bytes.len();
            if end > start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            lines.push((start, end));
        }

        lines
    }

    fn next_line_bounds(&mut self) -> Option<(usize, usize)> {
        let bounds = self.lines.get(self.position).copied()?;
        self.position += 1;
        Some(bounds)
    }
}

impl Producer for LineProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let Some((start, end)) = self.next_line_bounds() else {
            return Ok(None);
        };

        Ok(Some(self.bytes[start..end].to_vec()))
    }

    fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        let Some((start, end)) = self.next_line_bounds() else {
            output.clear();
            return Ok(false);
        };

        output.clear();
        output.extend_from_slice(&self.bytes[start..end]);
        Ok(true)
    }

    fn size(&self) -> usize {
        self.lines.len()
    }

    fn skip(&mut self, count: usize) -> Result<usize, String> {
        let remaining = self.lines.len().saturating_sub(self.position);
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
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::Producer;

    use super::LineProducer;

    fn drain_into(producer: &mut dyn Producer) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let mut candidate = Vec::new();

        while producer
            .next_into(&mut candidate)
            .expect("producer should not error")
        {
            values.push(candidate.clone());
        }

        values
    }

    fn temp_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("pdfrip-{name}-{}-{unique}.txt", std::process::id()))
    }

    #[test]
    fn handles_crlf_and_missing_trailing_newline() {
        let path = temp_path("dictionary");
        std::fs::write(&path, b"alpha\r\nbeta\r\ngamma").expect("wordlist should be writable");

        let mut producer =
            LineProducer::try_from_path(path.to_str().expect("path should be utf-8"))
                .expect("wordlist should build");
        let mut values = Vec::new();

        while let Some(value) = producer.next().expect("wordlist should not error") {
            values.push(String::from_utf8(value).expect("wordlist values should stay utf-8"));
        }

        assert_eq!(producer.size(), 3);
        assert_eq!(values, vec!["alpha", "beta", "gamma"]);

        std::fs::remove_file(&path).expect("temporary wordlist should be removable");
    }

    #[test]
    fn skip_advances_without_replaying_lines() {
        let path = temp_path("dictionary-skip");
        std::fs::write(&path, b"alpha\nbeta\ngamma\ndelta\n").expect("wordlist should be writable");

        let mut producer =
            LineProducer::try_from_path(path.to_str().expect("path should be utf-8"))
                .expect("wordlist should build");

        assert_eq!(producer.skip(2).unwrap(), 2);
        assert_eq!(producer.next().unwrap(), Some(b"gamma".to_vec()));
        assert_eq!(producer.next().unwrap(), Some(b"delta".to_vec()));
        assert_eq!(producer.next().unwrap(), None);

        std::fs::remove_file(&path).expect("temporary wordlist should be removable");
    }

    #[test]
    fn preserves_blank_lines_as_empty_password_candidates() {
        let path = temp_path("dictionary-blank-lines");
        std::fs::write(&path, b"\nalpha\n\n").expect("wordlist should be writable");

        let mut producer =
            LineProducer::try_from_path(path.to_str().expect("path should be utf-8"))
                .expect("wordlist should build");

        assert_eq!(producer.size(), 3);
        assert_eq!(producer.next().unwrap(), Some(Vec::new()));
        assert_eq!(producer.next().unwrap(), Some(b"alpha".to_vec()));
        assert_eq!(producer.next().unwrap(), Some(Vec::new()));
        assert_eq!(producer.next().unwrap(), None);

        std::fs::remove_file(&path).expect("temporary wordlist should be removable");
    }

    #[test]
    fn next_into_matches_line_iteration_order() {
        let path = temp_path("dictionary-next-into");
        std::fs::write(&path, b"alpha\nbeta\n\ngamma\n").expect("wordlist should be writable");

        let expected = {
            let mut producer =
                LineProducer::try_from_path(path.to_str().expect("path should be utf-8"))
                    .expect("wordlist should build");
            let mut values = Vec::new();
            while let Some(value) = producer.next().expect("wordlist should not error") {
                values.push(value);
            }
            values
        };

        let mut producer =
            LineProducer::try_from_path(path.to_str().expect("path should be utf-8"))
                .expect("wordlist should build");
        assert_eq!(drain_into(&mut producer), expected);

        std::fs::remove_file(&path).expect("temporary wordlist should be removable");
    }
}
