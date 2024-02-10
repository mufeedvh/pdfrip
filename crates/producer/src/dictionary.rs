use std::{
    fs,
    io::{BufRead, BufReader},
};

use super::Producer;

pub struct LineProducer {
    inner: Box<dyn BufRead>,
    size: usize,
}

impl LineProducer {
    pub fn from(path: &str) -> Self {
        let lines = bytecount::count(&fs::read(path).unwrap(), b'\n');

        let file = fs::File::open(path).unwrap();
        let reader = BufReader::new(file);

        Self {
            inner: Box::from(reader),
            size: lines,
        }
    }
}

impl Producer for LineProducer {
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut bytes = Vec::new();
        match self.inner.read_until(b'\n', &mut bytes) {
            Ok(0) => Ok(None),
            Ok(_) => {
                // read_until() ends with a newline char unless it is the last line of the file.
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                }
                Ok(Some(bytes))
            }
            Err(err) => {
                debug!("Unable to read from reader: {}", err);
                Err(String::from("Error reading from wordlist file."))
            }
        }
    }

    fn size(&self) -> usize {
        self.size
    }
}
