use super::{write_decimal_usize, Producer};

#[derive(Clone)]
struct NumericRange {
    start: usize,
    width: usize,
    size: usize,
}

#[derive(Clone)]
enum QueryKind {
    Literal {
        value: Vec<u8>,
    },
    Numeric {
        prefix: Vec<u8>,
        suffix: Vec<u8>,
        ranges: Vec<NumericRange>,
    },
}

/// Generates candidates from a bounded custom-query pattern.
///
/// The current implementation supports either a literal-only query or a single numeric range
/// block such as `ALICE{1-9999}`. This keeps the producer finite and exactly countable while also
/// enabling cheap resume skips through a stable candidate index.
#[derive(Clone)]
pub struct CustomQuery {
    kind: QueryKind,
    size: usize,
    position: usize,
}

impl CustomQuery {
    /// Builds a custom-query generator and panics if the query is invalid.
    ///
    /// This is retained for compatibility with existing internal callers. User-facing paths should
    /// prefer [`CustomQuery::try_new`] so invalid patterns become regular errors instead of
    /// process-terminating panics.
    pub fn new(query: &str, add_preceding_zeros: bool) -> Self {
        Self::try_new(query, add_preceding_zeros).expect("custom-query should be valid")
    }

    /// Parses a bounded custom query into a deterministic candidate generator.
    ///
    /// When `add_preceding_zeros` is enabled, numeric padding width is derived from the declared
    /// upper bound for each range, which fixes the historical `{0-99}` bug. Returns an error for
    /// malformed braces, invalid numeric bounds, or search spaces that cannot be counted exactly.
    pub fn try_new(query: &str, add_preceding_zeros: bool) -> Result<Self, String> {
        let size;
        let kind = match Self::parse_query(query)? {
            ParsedQuery::Literal(value) => {
                size = 1;
                QueryKind::Literal {
                    value: value.into_bytes(),
                }
            }
            ParsedQuery::Numeric {
                prefix,
                body,
                suffix,
            } => {
                let (ranges, total_size) = Self::parse_ranges(&body, add_preceding_zeros)?;
                size = total_size;
                QueryKind::Numeric {
                    prefix: prefix.into_bytes(),
                    suffix: suffix.into_bytes(),
                    ranges,
                }
            }
        };

        Ok(Self {
            kind,
            size,
            position: 0,
        })
    }

    fn parse_query(query: &str) -> Result<ParsedQuery, String> {
        let opening_braces = query.matches('{').count();
        let closing_braces = query.matches('}').count();

        if opening_braces == 0 && closing_braces == 0 {
            return Ok(ParsedQuery::Literal(query.to_string()));
        }

        if opening_braces != closing_braces {
            return Err(String::from("custom-query must use balanced braces"));
        }

        if opening_braces > 1 {
            return Err(String::from(
                "custom-query currently supports only one numeric range block",
            ));
        }

        let open = query
            .find('{')
            .ok_or_else(|| String::from("custom-query is missing an opening brace"))?;
        let close = query
            .find('}')
            .ok_or_else(|| String::from("custom-query is missing a closing brace"))?;

        if close < open {
            return Err(String::from(
                "custom-query closing brace must come after the opening brace",
            ));
        }

        let prefix = query[..open].to_string();
        let body = query[open + 1..close].to_string();
        let suffix = query[close + 1..].to_string();

        if body.trim().is_empty() {
            return Err(String::from("custom-query range block must not be empty"));
        }

        Ok(ParsedQuery::Numeric {
            prefix,
            body,
            suffix,
        })
    }

    fn parse_ranges(
        body: &str,
        add_preceding_zeros: bool,
    ) -> Result<(Vec<NumericRange>, usize), String> {
        let mut total_size = 0usize;
        let mut ranges = Vec::new();

        for range in body.split(',').map(str::trim) {
            let (parsed_range, range_size) = Self::parse_range(range, add_preceding_zeros)?;
            total_size = total_size.checked_add(range_size).ok_or_else(|| {
                String::from("custom-query search space is too large to count exactly")
            })?;
            ranges.push(parsed_range);
        }

        Ok((ranges, total_size))
    }

    fn parse_range(
        range: &str,
        add_preceding_zeros: bool,
    ) -> Result<(NumericRange, usize), String> {
        let bounds = range.split('-').map(str::trim).collect::<Vec<_>>();
        if bounds.len() != 2 || bounds.iter().any(|bound| bound.is_empty()) {
            return Err(format!(
                "invalid custom-query range '{range}'; expected START-END"
            ));
        }

        let start = bounds[0].parse::<usize>().map_err(|err| {
            format!(
                "invalid custom-query range start '{}' in '{range}': {err}",
                bounds[0]
            )
        })?;
        let end = bounds[1].parse::<usize>().map_err(|err| {
            format!(
                "invalid custom-query range end '{}' in '{range}': {err}",
                bounds[1]
            )
        })?;

        if start > end {
            return Err(format!(
                "invalid custom-query range '{range}'; start must not exceed end"
            ));
        }

        let size = end
            .checked_sub(start)
            .and_then(|delta| delta.checked_add(1))
            .ok_or_else(|| String::from("custom-query range is too large to count exactly"))?;

        let width = if add_preceding_zeros {
            bounds[1].len()
        } else {
            0
        };

        Ok((NumericRange { start, width, size }, size))
    }

    fn render_current_into(&self, output: &mut Vec<u8>) -> Result<(), String> {
        match &self.kind {
            QueryKind::Literal { value } => {
                output.clear();
                output.extend_from_slice(value);
                Ok(())
            }
            QueryKind::Numeric {
                prefix,
                suffix,
                ranges,
            } => {
                let mut offset = self.position;

                for range in ranges {
                    if offset >= range.size {
                        offset -= range.size;
                        continue;
                    }

                    let value = range.start.checked_add(offset).ok_or_else(|| {
                        String::from("custom-query range overflowed while generating candidates")
                    })?;

                    output.clear();
                    output.extend_from_slice(prefix);
                    write_decimal_usize(output, value, range.width);
                    output.extend_from_slice(suffix);
                    return Ok(());
                }

                Err(String::from(
                    "custom-query offset exceeded the available search space",
                ))
            }
        }
    }
}

impl Producer for CustomQuery {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.position >= self.size {
            return Ok(None);
        }

        let mut candidate = Vec::new();
        self.render_current_into(&mut candidate)?;
        self.position += 1;
        Ok(Some(candidate))
    }

    fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        if self.position >= self.size {
            output.clear();
            return Ok(false);
        }

        self.render_current_into(output)?;
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

enum ParsedQuery {
    Literal(String),
    Numeric {
        prefix: String,
        body: String,
        suffix: String,
    },
}

#[cfg(test)]
mod tests {
    use crate::Producer;

    use super::CustomQuery;

    fn drain_into(producer: &mut dyn Producer) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let mut candidate = Vec::new();

        while producer.next_into(&mut candidate).unwrap() {
            values.push(candidate.clone());
        }

        values
    }

    #[test]
    fn literal_only_query_emits_once() {
        let mut producer = CustomQuery::new("ALICE", false);

        assert_eq!(producer.size(), 1);
        assert_eq!(producer.next().unwrap(), Some(b"ALICE".to_vec()));
        assert_eq!(producer.next().unwrap(), None);
    }

    #[test]
    fn zero_padding_uses_the_declared_upper_bound_width() {
        let mut producer = CustomQuery::new("ID{0-9}", true);
        let mut values = Vec::new();

        while let Some(value) = producer.next().expect("query should not error") {
            values.push(String::from_utf8(value).expect("query should stay utf-8"));
        }

        assert_eq!(values.first().map(String::as_str), Some("ID0"));
        assert_eq!(values.last().map(String::as_str), Some("ID9"));
        assert!(!values.iter().any(|value| value == "ID00"));
    }

    #[test]
    fn malformed_queries_return_errors() {
        assert!(CustomQuery::try_new("ALICE{", false).is_err());
        assert!(CustomQuery::try_new("ALICE{}", false).is_err());
        assert!(CustomQuery::try_new("ALICE{nope-1}", false).is_err());
        assert!(CustomQuery::try_new("ALICE{10-1}", false).is_err());
    }

    #[test]
    fn skip_moves_into_the_expected_numeric_range() {
        let mut producer = CustomQuery::new("ID{1-3,10-12}", false);

        assert_eq!(producer.skip(4).unwrap(), 4);
        assert_eq!(producer.next().unwrap(), Some(b"ID11".to_vec()));
    }

    #[test]
    fn next_into_matches_custom_query_iteration_order() {
        let expected = {
            let mut producer = CustomQuery::new("ID{1-3,10-12}", true);
            let mut values = Vec::new();
            while let Some(value) = producer.next().unwrap() {
                values.push(value);
            }
            values
        };

        let mut producer = CustomQuery::new("ID{1-3,10-12}", true);
        assert_eq!(drain_into(&mut producer), expected);
    }
}
