use super::Producer;

pub struct DateProducer {
    current: usize,
    end: usize,
    inner: Box<dyn Iterator<Item = String>>,
    counter: usize,
}

/// Pregenerates all naively "valid" combinations of days and months.
/// This is probably fine since it's a constant amount anyways.
fn pregenerate_dates() -> Vec<String> {
    let mut results = Vec::new();
    for month in 1..13 {
        for date in 1..32 {
            let date: String = if date < 10 {
                format!("0{}", date)
            } else {
                date.to_string()
            };

            let month: String = if month < 10 {
                format!("0{}", month)
            } else {
                month.to_string()
            };

            results.push(format!("{}{}", date, month))
        }
    }

    results
}

impl DateProducer {
    pub fn new(start: usize, end: usize) -> Self {
        // Note that we will always have the same amount of months and days since we are doing this naively.
        // The only part that varies is the year, so why not pre-generate days and months?
        let dates = pregenerate_dates().into_iter().cycle();

        Self {
            current: start,
            end,
            inner: Box::from(dates),
            counter: 0,
        }
    }
}

impl Producer for DateProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.current > self.end {
            debug!("stopping at year {}", self.current);
            Ok(None)
        } else {
            // We need to know when we have finished the year so we can start working on the next
            if self.counter == 12 * 31 {
                self.counter = 0;
                self.current += 1;
            } else {
                self.counter += 1;
            }

            let next = self.inner.next().unwrap();

            let password = format!("{:04}{:04}", next, self.current).into_bytes();
            debug!(
                "Sending {} from DateProducer",
                String::from_utf8_lossy(&password)
            );
            Ok(Some(password))
        }
    }

    fn size(&self) -> usize {
        let mut years = self.end - self.current;
        if years == 0 {
            years = 1;
        }
        12 * 31 * years
    }
}

#[cfg(test)]
mod tests {
    use crate::Producer;

    use super::DateProducer;

    #[test]
    fn instantiate_instance() {
        let _ = DateProducer::new(1337, 1338);
    }

    #[test]
    fn test_size_is_correct() {
        let producer = DateProducer::new(1337, 1338);
        let size = producer.size();
        let passwords = producer.inner.take(size).collect::<Vec<String>>();
        assert_eq!(size, passwords.len())
    }

    #[test]
    fn can_run_1_year() {
        let producer = DateProducer::new(1337, 1337);
        let size = 12 * 31;
        let passwords = producer.inner.take(size).collect::<Vec<String>>();
        assert_eq!(size, passwords.len())
    }
}
