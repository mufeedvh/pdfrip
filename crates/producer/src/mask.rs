use super::Producer;

#[derive(Clone, Debug)]
enum MaskSegment {
    Literal(Vec<u8>),
    Class {
        charset: Vec<u8>,
        min_reps: usize,
        max_reps: usize,
        variant_counts: Vec<usize>,
        variants: usize,
    },
}

impl MaskSegment {
    fn variants(&self) -> usize {
        match self {
            Self::Literal(_) => 1,
            Self::Class { variants, .. } => *variants,
        }
    }

    fn max_len(&self) -> usize {
        match self {
            Self::Literal(value) => value.len(),
            Self::Class { max_reps, .. } => *max_reps,
        }
    }

    fn render_into(&self, mut offset: usize, output: &mut Vec<u8>) -> Result<(), String> {
        match self {
            Self::Literal(value) => {
                output.extend_from_slice(value);
                Ok(())
            }
            Self::Class {
                charset,
                min_reps,
                variant_counts,
                ..
            } => {
                let radix = charset.len();
                for (repetition_offset, count) in variant_counts.iter().copied().enumerate() {
                    if offset >= count {
                        offset -= count;
                        continue;
                    }

                    let reps = min_reps + repetition_offset;
                    let start = output.len();
                    output.resize(start + reps, 0);

                    let mut value = offset;
                    for byte in &mut output[start..] {
                        *byte = charset[value % radix];
                        value /= radix;
                    }
                    return Ok(());
                }

                Err(String::from(
                    "mask segment offset exceeded its search space",
                ))
            }
        }
    }
}

/// Generates candidates from a bounded mask DSL.
///
/// Supported placeholders:
/// - `?l` lowercase ASCII letters
/// - `?u` uppercase ASCII letters
/// - `?d` decimal digits
/// - `?s` printable ASCII that is neither a letter nor a digit
/// - `?a` all printable ASCII characters
///
/// Repetition can be expressed as either `{n}` or `{min,max}` after a class token, for example
/// `?u{4}?d{4}` or `DOC-?d{2,4}`. A literal `?` can be written as `??`.
#[derive(Clone)]
pub struct MaskProducer {
    segments: Vec<MaskSegment>,
    suffix_products: Vec<usize>,
    max_candidate_len: usize,
    size: usize,
    position: usize,
}

impl MaskProducer {
    /// Builds a mask producer and panics if the mask is invalid.
    pub fn new(mask: &str) -> Self {
        Self::try_new(mask).expect("mask should be valid")
    }

    /// Parses a bounded mask into a deterministic, countable producer.
    pub fn try_new(mask: &str) -> Result<Self, String> {
        let segments = parse_mask(mask)?;
        let mut size = 1usize;
        let mut max_candidate_len = 0usize;

        for segment in &segments {
            size = size
                .checked_mul(segment.variants())
                .ok_or_else(|| String::from("mask search space is too large to count exactly"))?;
            max_candidate_len = max_candidate_len
                .checked_add(segment.max_len())
                .ok_or_else(|| String::from("mask candidate length overflowed"))?;
        }

        let mut suffix_products = vec![1usize; segments.len()];
        for index in (0..segments.len()).rev() {
            if index + 1 < segments.len() {
                suffix_products[index] = suffix_products[index + 1]
                    .checked_mul(segments[index + 1].variants())
                    .ok_or_else(|| String::from("mask suffix product overflowed"))?;
            }
        }

        Ok(Self {
            segments,
            suffix_products,
            max_candidate_len,
            size,
            position: 0,
        })
    }

    fn render_candidate_into(&self, mut offset: usize, output: &mut Vec<u8>) -> Result<(), String> {
        output.clear();
        output.reserve(self.max_candidate_len.saturating_sub(output.capacity()));

        for (index, segment) in self.segments.iter().enumerate() {
            let stride = self.suffix_products[index];
            let local_offset = if stride == 0 { 0 } else { offset / stride };
            if stride != 0 {
                offset %= stride;
            }
            segment.render_into(local_offset, output)?;
        }

        Ok(())
    }
}

impl Producer for MaskProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.position >= self.size {
            return Ok(None);
        }

        let mut candidate = Vec::new();
        self.render_candidate_into(self.position, &mut candidate)?;
        self.position += 1;
        Ok(Some(candidate))
    }

    fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        if self.position >= self.size {
            output.clear();
            return Ok(false);
        }

        self.render_candidate_into(self.position, output)?;
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

fn parse_mask(mask: &str) -> Result<Vec<MaskSegment>, String> {
    if mask.is_empty() {
        return Err(String::from("mask must not be empty"));
    }

    let mut segments = Vec::new();
    let mut literal = String::new();
    let chars = mask.chars().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < chars.len() {
        if chars[index] != '?' {
            literal.push(chars[index]);
            index += 1;
            continue;
        }

        if index + 1 >= chars.len() {
            return Err(String::from("mask ends with an incomplete class token"));
        }

        if chars[index + 1] == '?' {
            literal.push('?');
            index += 2;
            continue;
        }

        if !literal.is_empty() {
            segments.push(MaskSegment::Literal(
                std::mem::take(&mut literal).into_bytes(),
            ));
        }

        let spec = chars[index + 1];
        let charset = mask_charset(spec).ok_or_else(|| {
            format!("unsupported mask class '?{spec}'; supported classes are ?l, ?u, ?d, ?s, ?a")
        })?;
        index += 2;

        let (min_reps, max_reps, consumed) = parse_repetition(&chars[index..])?;
        index += consumed;

        let mut variants = 0usize;
        let mut variant_counts = Vec::with_capacity(max_reps - min_reps + 1);
        for reps in min_reps..=max_reps {
            let count = charset.len().checked_pow(reps as u32).ok_or_else(|| {
                format!("mask class '?{spec}' is too large to count exactly at repetition {reps}")
            })?;
            variants = variants
                .checked_add(count)
                .ok_or_else(|| String::from("mask class variants overflowed"))?;
            variant_counts.push(count);
        }

        segments.push(MaskSegment::Class {
            charset,
            min_reps,
            max_reps,
            variant_counts,
            variants,
        });
    }

    if !literal.is_empty() {
        segments.push(MaskSegment::Literal(literal.into_bytes()));
    }

    Ok(segments)
}

fn parse_repetition(chars: &[char]) -> Result<(usize, usize, usize), String> {
    if chars.first() != Some(&'{') {
        return Ok((1, 1, 0));
    }

    let mut end = None;
    for (index, ch) in chars.iter().enumerate().skip(1) {
        if *ch == '}' {
            end = Some(index);
            break;
        }
    }
    let end = end.ok_or_else(|| String::from("mask repetition is missing a closing brace"))?;
    let body = chars[1..end].iter().collect::<String>();

    let (min_reps, max_reps) = if let Some((min, max)) = body.split_once(',') {
        let min_reps = min
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("invalid mask repetition start '{min}': {err}"))?;
        let max_reps = max
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("invalid mask repetition end '{max}': {err}"))?;
        (min_reps, max_reps)
    } else {
        let reps = body
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("invalid mask repetition '{body}': {err}"))?;
        (reps, reps)
    };

    if min_reps == 0 || max_reps == 0 {
        return Err(String::from("mask repetition values must be at least 1"));
    }
    if min_reps > max_reps {
        return Err(String::from(
            "mask repetition start must not exceed the repetition end",
        ));
    }

    Ok((min_reps, max_reps, end + 1))
}

fn mask_charset(spec: char) -> Option<Vec<u8>> {
    let charset = match spec {
        'l' => (b'a'..=b'z').collect::<Vec<_>>(),
        'u' => (b'A'..=b'Z').collect::<Vec<_>>(),
        'd' => (b'0'..=b'9').collect::<Vec<_>>(),
        's' => std::iter::once(b' ')
            .chain(b'!'..=b'/')
            .chain(b':'..=b'@')
            .chain(b'['..=b'`')
            .chain(b'{'..=b'~')
            .collect::<Vec<_>>(),
        'a' => std::iter::once(b' ').chain(b'!'..=b'~').collect::<Vec<_>>(),
        _ => return None,
    };

    Some(charset)
}

#[cfg(test)]
mod tests {
    use crate::Producer;

    use super::MaskProducer;

    fn drain_into(producer: &mut dyn Producer) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let mut candidate = Vec::new();

        while producer.next_into(&mut candidate).unwrap() {
            values.push(candidate.clone());
        }

        values
    }

    #[test]
    fn fixed_repetition_masks_are_countable() {
        let mut producer = MaskProducer::new("ID-?d{2}");

        assert_eq!(producer.size(), 100);
        assert_eq!(producer.next().unwrap(), Some(b"ID-00".to_vec()));
        assert_eq!(producer.skip(8).unwrap(), 8);
        assert_eq!(producer.next().unwrap(), Some(b"ID-90".to_vec()));
    }

    #[test]
    fn bounded_repetition_masks_expand_in_order() {
        let mut producer = MaskProducer::new("?u{1,2}");

        assert_eq!(producer.next().unwrap(), Some(b"A".to_vec()));
        assert_eq!(producer.skip(25).unwrap(), 25);
        assert_eq!(producer.next().unwrap(), Some(b"AA".to_vec()));
    }

    #[test]
    fn literal_question_mark_can_be_escaped() {
        let mut producer = MaskProducer::new("DOC??-?d");
        assert_eq!(producer.next().unwrap(), Some(b"DOC?-0".to_vec()));
    }

    #[test]
    fn malformed_masks_return_errors() {
        assert!(MaskProducer::try_new("").is_err());
        assert!(MaskProducer::try_new("?").is_err());
        assert!(MaskProducer::try_new("?x").is_err());
        assert!(MaskProducer::try_new("?d{2,1}").is_err());
    }

    #[test]
    fn next_into_matches_mask_iteration_order() {
        let expected = {
            let mut producer = MaskProducer::new("DOC-?u{1,2}?d");
            let mut values = Vec::new();
            while let Some(value) = producer.next().unwrap() {
                values.push(value);
            }
            values
        };

        let mut producer = MaskProducer::new("DOC-?u{1,2}?d");
        assert_eq!(drain_into(&mut producer), expected);
    }
}
