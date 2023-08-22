use super::Producer;

pub struct DateProducer {
    year: usize,
    inner: Box<dyn Iterator<Item = String>>,
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
    pub fn new(year: usize) -> Self {
        // Note that we will always have the same amount of months and days since we are doing this naively.
        // The only part that varies is the year, so why not pre-generate days and months?
        let dates = pregenerate_dates().into_iter();

        Self {
            year,
            inner: Box::from(dates),
        }
    }
}

impl Producer for DateProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let next = self.inner.next();
        match next {
            Some(datemonth) => {
                let password = format!("{}{}", datemonth, self.year).into_bytes();
                Ok(Some(password))
            }
            None => Ok(None),
        }
    }

    fn size(&self) -> usize {
        12 * 31
    }
}

#[cfg(test)]
mod tests {
    use crate::core::production::Producer;

    use super::DateProducer;

    #[test]
    fn instantiate_instance() {
        let _ = DateProducer::new(1337);
    }

    #[test]
    fn test_size_is_correct() {
        let producer = DateProducer::new(1337);
        let size = producer.size();
        let passwords = producer.inner.collect::<Vec<String>>();
        assert_eq!(size, passwords.len())
    }
}
