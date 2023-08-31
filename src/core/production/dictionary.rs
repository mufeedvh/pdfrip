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
        // TODO: This will be slow on large files, so we might want to skip this
        // depending on the filesize. Way better than the original implementation though.
        // An idea is to generalize the "engine" to give control of the progress bar to the producer
        // thus allowing us to e.g. replace it with a spinning icon or something in situations like these
        let lines = fs::read(&path)
            .unwrap()
            .iter()
            .filter(|x| {
                if let Some(y) = char::from_u32(**x as u32) {
                    y == '\n'
                } else {
                    false
                }
            })
            .count();
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
            Ok(line) if line == 0 => Ok(None),
            Ok(_) => {
                // read_until() ends with a newline char unless it is the last line of the file.
                if bytes.last() == Some(&b'\n') { bytes.pop(); }
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
