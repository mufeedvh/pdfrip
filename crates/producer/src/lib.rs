//! Deterministic password-candidate producers used by the cracking engine.
//!
//! Every producer in this crate is finite, countable, and resumable. Those properties are
//! important because the engine now relies on exact candidate counts for progress reporting,
//! checkpoint persistence, and resume validation. Implementations should therefore keep their
//! iteration order stable and ensure [`Producer::size`] always matches the number of values that
//! can be emitted.

#[macro_use]
extern crate log;

/// Generates password candidates for the engine.
///
/// Implementations must be deterministic and finite. The engine assumes that the first `n`
/// candidates produced by repeated [`Producer::next`] calls always form the same prefix so a
/// cancelled job can resume by skipping exactly `n` verified attempts.
pub trait Producer: Send {
    /// Returns the next candidate in the producer's deterministic sequence.
    ///
    /// `Ok(Some(bytes))` yields a password candidate, `Ok(None)` signals normal exhaustion, and
    /// `Err` reports a producer-specific failure that should stop the job.
    fn next(&mut self) -> Result<Option<Vec<u8>>, String>;

    /// Writes the next candidate into `output`, reusing its allocation when possible.
    ///
    /// Hot producers should override this method so worker threads can keep a single reusable
    /// buffer for candidate generation instead of allocating a fresh `Vec<u8>` for every attempt.
    /// The default implementation preserves backwards compatibility by delegating to
    /// [`Producer::next`]. On success it leaves `output` containing the emitted candidate. On
    /// exhaustion it clears `output` and returns `Ok(false)`.
    fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        match self.next()? {
            Some(candidate) => {
                output.clear();
                output.extend_from_slice(&candidate);
                Ok(true)
            }
            None => {
                output.clear();
                Ok(false)
            }
        }
    }

    /// Returns the exact number of candidates this producer can emit.
    fn size(&self) -> usize;

    /// Advances the producer without allocating the skipped candidates.
    ///
    /// The default implementation is correct but potentially expensive because it repeatedly calls
    /// [`Producer::next`]. Producers with cheap random access should override this method so
    /// checkpoint resume stays fast even for large search spaces.
    fn skip(&mut self, count: usize) -> Result<usize, String> {
        let mut skipped = 0usize;

        while skipped < count {
            match self.next()? {
                Some(_) => skipped += 1,
                None => break,
            }
        }

        Ok(skipped)
    }

    /// Returns a boxed clone of the producer when worker-local sharding is supported.
    ///
    /// The engine uses this optional capability to eliminate the single shared-producer bottleneck
    /// on multi-worker runs. A returned clone must preserve the producer's current deterministic
    /// cursor so cloned workers can seek into disjoint keyspace ranges without changing the global
    /// candidate order. Returning `None` is always valid and causes the engine to fall back to the
    /// coordinator-driven batching path.
    fn boxed_clone(&self) -> Option<Box<dyn Producer>> {
        None
    }
}

/// Appends a decimal `usize` to `output` with an optional minimum width.
///
/// The function never allocates on its own; callers can clear and reuse `output` across many
/// candidates. `min_width` behaves like the width in Rust formatting strings: values shorter than
/// the width are left-padded with ASCII `0`, while wider values are emitted in full without
/// truncation.
pub(crate) fn write_decimal_usize(output: &mut Vec<u8>, mut value: usize, min_width: usize) {
    let mut reversed_digits = [0u8; 39];
    let mut digit_count = 0usize;

    loop {
        reversed_digits[digit_count] = b'0' + (value % 10) as u8;
        digit_count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    let total_width = min_width.max(digit_count);
    output.reserve(total_width);
    for _ in digit_count..total_width {
        output.push(b'0');
    }
    for index in (0..digit_count).rev() {
        output.push(reversed_digits[index]);
    }
}

/// Producers that handle dictionary-style attacks.
pub mod dictionary;

/// Producers that handle number-range attacks.
pub mod number_ranges;

/// Parses a custom query and generates passwords accordingly.
pub mod custom_query;

/// Handles creating passwords matching dates in configurable day/month/year formats.
pub mod dates;

/// Generates candidates from a bounded mask DSL.
pub mod mask;

/// Generates candidates that must contain one of a supplied set of words.
pub mod contains_word;

/// Does a traditional brute-force search through all possible printable-ASCII combinations.
pub mod default_query;
