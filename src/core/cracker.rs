/// We require cracker implementations to support being sent between threads.
pub trait Cracker: Sync + Send {
    /// Attempt to crack the cryptography using the password, return true on success.
    fn attempt(&self, password: &[u8]) -> bool;
}

pub mod pdf {
    use std::{fs, io};

    use pdf::file::FileOptions;

    use super::Cracker;

    pub struct PDFCracker(Vec<u8>);

    impl PDFCracker {
        pub fn from_file(path: &str) -> Result<Self, io::Error> {
            let pdf_file: Vec<u8> = fs::read(path)?;
            Ok(Self(pdf_file))
        }
    }

    impl Cracker for PDFCracker {
        fn attempt(&self, password: &[u8]) -> bool {
            FileOptions::cached()
                .password(password)
                .load(self.0.as_ref())
                .is_ok()
        }
    }
}
