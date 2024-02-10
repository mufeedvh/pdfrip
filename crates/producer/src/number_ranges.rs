use super::Producer;

pub struct RangeProducer {
    padding_len: usize,
    inner: Box<dyn Iterator<Item = usize>>,
    size: usize,
}

impl RangeProducer {
    pub fn new(padding_len: usize, lower_bound: usize, upper_bound: usize) -> Self {
        Self {
            padding_len,
            inner: Box::from(lower_bound..upper_bound),
            size: upper_bound - lower_bound,
        }
    }
}

impl Producer for RangeProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let next = self.inner.next();
        match next {
            Some(number) => {
                let data = format!("{:0>width$}", number, width = self.padding_len).into_bytes();
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    fn size(&self) -> usize {
        self.size
    }
}
