use super::Producer;

pub struct CustomQuery {
    inner: Box<dyn Iterator<Item = usize>>,
    size: usize,
    prefix: String,
    suffix: String,
    min_digits: usize,
}

impl CustomQuery {
    pub fn new(query: &str, add_preceding_zeros: bool) -> Self {
        let mut start_parse = false;
        let mut end_parse = false;
        let mut next_range = false;
        let mut start_range = String::new();
        let mut end_range = String::new();

        let mut prefix = String::new();
        let mut range_enclave = String::new();
        let mut suffix = String::new();
        // TODO: This parsing is ugly. Can probably be done with a simple regex,  but I won't try to figure
        // out how the original author intended this to work.
        for c in query.chars() {
            match c {
                '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '0' => {
                    if !next_range {
                        start_range.push(c)
                    } else {
                        end_range.push(c)
                    }

                    if start_parse {
                        range_enclave.push(c)
                    }
                }
                '-' => {
                    if !next_range && start_parse {
                        next_range = true;
                    } else {
                        if !start_parse {
                            prefix.push(c)
                        }
                        if end_parse {
                            suffix.push(c)
                        }
                    }
                    range_enclave.push(c)
                }
                '{' => {
                    start_parse = true;
                    range_enclave.push(c)
                }
                '}' => {
                    end_parse = true;
                    range_enclave.push(c)
                }
                _ => {
                    if !start_parse {
                        prefix.push(c)
                    }
                    if end_parse {
                        suffix.push(c)
                    }
                }
            }
        }
        let start_range = start_range.parse::<usize>().unwrap();
        let end_range = end_range.parse::<usize>().unwrap();
        let size = end_range - start_range;

        let iterator = Box::from(start_range..end_range);
        Self {
            inner: iterator,
            size,
            prefix,
            suffix,
            min_digits: if add_preceding_zeros {
                end_range.ilog10() as usize
            } else {
                0
            },
        }
    }
}

impl Producer for CustomQuery {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let num = self.inner.next();
        match num {
            Some(value) => {
                let full_number = format!("{:0>width$}", value, width = self.min_digits);
                Ok(Some(format!("{}{}{}", self.prefix, full_number, self.suffix).into_bytes()))
            }
            None => Ok(None),
        }
    }

    fn size(&self) -> usize {
        self.size
    }
}
