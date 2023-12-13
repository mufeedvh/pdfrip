pub mod pdf {
    use std::{fs, io};

    use pdf::file::FileOptions;

    #[derive(Clone)]
    pub struct PDFCracker(Vec<u8>);

    impl PDFCracker {
        pub fn from_file(path: &str) -> Result<Self, io::Error> {
            let pdf_file: Vec<u8> = fs::read(path)?;
            Ok(Self(pdf_file))
        }
    }

    impl PDFCracker {
        /// Attempt to crack the cryptography using the password, return true on success.
        pub fn attempt(&self, password: &[u8]) -> bool {
            FileOptions::cached()
                .password(password)
                .load(self.0.as_ref())
                .is_ok()
        }
    }
}
