use colored::*;
use indicatif::ProgressBar;
use pdf::file::File;
use rayon::prelude::*;

use std::fs;
use std::io;
use std::path::Path;
use std::process;


pub struct PDFRip {
    pub filepath: String,
    pub wordlist_path: Option<String>,
    pub num_bruteforce: Option<String>,
    pub preceding_zeros_enabled: bool,
}

impl PDFRip {
    #[inline]
    pub fn decrypt_pdf(pdf_bytes: Vec<u8>, password: &[u8]) -> bool {
        match File::from_data_password(pdf_bytes, password) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn win(&self, password: &str, time_elapsed: Option<u128>) {
        info!("{} :: ", &self.filepath.red());

        println!("{}", password.bold().yellow());

        if let Some(time_elapsed) = time_elapsed {
            info!("Cracked in {} milliseconds", time_elapsed);
        }

        process::exit(0)
    }

    /* 
        Start worker threads
        Main thread feeds data to channels from which workers read from.

        Producer takes a write channel & extra params and does whatever it is implemented to do.
        It outputs Arc<Vec<u8>> or similar.
    
     */
    pub fn crack(&self) -> io::Result<()> {
        Self::sanity_check(&self);

        info!("PDF File: {}\n", &self.filepath.bold().red());

        let pdf_file = fs::read(&self.filepath)?;

        if let Some(wordlist_path) = &self.wordlist_path {
            info!("Wordlist File: {}\n\n", wordlist_path.bold().red());

            let wordlist_bytes = fs::read(wordlist_path)?;
            let wordlist = String::from_utf8_lossy(&wordlist_bytes);

            let progress_bar = ProgressBar::new(wordlist.matches('\n').count() as u64);
            progress_bar.set_draw_delta(1000);

            wordlist.par_lines().for_each(|password| {
                if Self::decrypt_pdf(pdf_file.clone(), password.as_bytes()) {
                    Self::win(&self, password, None)
                }
                progress_bar.inc(1);
            });

            progress_bar.finish();
        }

        if let Some(num_bruteforce_range) = &self.num_bruteforce {
            let parts = num_bruteforce_range.split("-").collect::<Vec<_>>();
            if parts.len() != 2 || num_bruteforce_range.starts_with("-") {
                error!(
                    "Invalid range format {}. (Use format: `1337-13337`)",
                    num_bruteforce_range
                );
                process::exit(1)
            }
            let lower = parts
                .first()
                .unwrap()
                .parse::<usize>()
                .expect("unable to parse lower number");
            let upper = parts
                .last()
                .unwrap()
                .parse::<usize>()
                .expect("unable to parse upper number");
            if upper < lower {
                error!(
                    "Invalid range format {}. (Use format: `1337-13337`)",
                    num_bruteforce_range
                );

                process::exit(1)
            }
            let range = upper - lower;

            info!(
                "Number Bruteforce Mode: {} payloads\n\n",
                range.to_string().bold().red()
            );

            let progress_bar = ProgressBar::new(range as u64);
            progress_bar.set_draw_delta(1000);

            (lower..upper).into_par_iter().for_each(|number| {
                let password = number.to_string();
                if Self::decrypt_pdf(pdf_file.clone(), password.as_bytes()) {
                    Self::win(&self, &password, None)
                }
                progress_bar.inc(1);
            });

            progress_bar.finish();
        }

        eprintln!("\nNone of those were the password :(, try building a custom query with `-q` if you know the password format!");

        Ok(())
    }

    pub fn sanity_check(&self) {
        if !Path::new(&self.filepath).is_file() {
            error!("The given PDF file `{}` does not exist", &self.filepath);
            process::exit(1)
        }

        if let Some(wordlist_path) = &self.wordlist_path {
            if !Path::new(&wordlist_path).is_file() {
                error!(
                    "The given wordlist file `{}` does not exist",
                    &wordlist_path
                );
                process::exit(1)
            }
        }

        match File::<Vec<u8>>::open_password(&self.filepath, b"dummytesttoomuchentropy12345") {
            Ok(_) => {
                error!("This PDF file is not encrypted.");
                process::exit(0)
            }
            Err(error) => {
                if error.to_string().contains("crypt_filters") {
                    error!("This PDF encryption algorithm isn't supported yet. :(",);
                    process::exit(0)
                } else if error.to_string().contains("file header is missing") {
                    error!("Invalid PDF file.");
                    process::exit(1)
                }
            }
        }
    }
}
