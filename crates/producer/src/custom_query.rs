use super::Producer;

pub struct CustomQuery {
    inner: Vec<Box<dyn Iterator<Item = usize>>>,
    size: usize,
    prefix: String,
    suffix: String,
    min_digits: usize,
}

impl CustomQuery {
    pub fn new(query: &str, add_preceding_zeros: bool) -> Self {
        let (prefix, ranges, suffix) = Self::parse_query(query);
        let mut size = 0;
        let mut inner = Vec::new();

        for range in ranges {
            let (start, end) = Self::parse_range(&range);
            size += end - start;
            let iterator: Box<dyn Iterator<Item = usize>> = Box::new(start..end);
            inner.push(iterator);
        }

        Self {
            inner,
            size,
            prefix,
            suffix,
            min_digits: if add_preceding_zeros {
                size.to_string().len()
            } else {
                0
            },
        }
    }

    fn parse_query(query: &str) -> (String, Vec<String>, String) {
        let mut parts = query.split('{');
        let prefix = parts.next().unwrap_or("").to_string();
        let ranges_and_suffix = parts.next().unwrap_or("");
        let mut parts = ranges_and_suffix.split('}');
        let ranges = parts
            .next()
            .unwrap_or("")
            .split(',')
            .map(|s| s.to_string())
            .collect();
        let suffix = parts.next().unwrap_or("").to_string();

        (prefix, ranges, suffix)
    }

    fn parse_range(range: &str) -> (usize, usize) {
        let mut bounds = range.split('-').map(|n| n.parse::<usize>().unwrap());
        let start = bounds.next().unwrap();
        let end = bounds.next().unwrap();

        (start, end + 1)
    }
}

impl Producer for CustomQuery {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        for iter in &mut self.inner {
            match iter.next() {
                Some(value) => {
                    let full_number = format!("{:0>width$}", value, width = self.min_digits);
                    return Ok(Some(
                        format!("{}{}{}", self.prefix, full_number, self.suffix).into_bytes(),
                    ));
                }
                None => continue,
            }
        }
        Ok(None)
    }

    fn size(&self) -> usize {
        self.size
    }
}
