use pdf::file::File;
use rayon::prelude::*;
use colored::*;
use indicatif::ProgressBar;

use std::path::Path;
use std::process;
use std::fs;

use crate::cli::messages::{
    Type, push_message
};

use crate::core::parsers;

pub struct PDFRip {
    pub filepath: String,
    pub wordlist_path: Option<String>,
    pub num_bruteforce: Option<String>,
    pub date_bruteforce: Option<String>,
    pub custom_query: Option<String>
}

impl PDFRip {
    #[inline]
    pub fn decrypt_pdf(pdf_bytes: Vec<u8>, password: &[u8]) -> bool {
        match File::from_data_password(pdf_bytes, password) {
            Ok(_) => true,
            Err(_) => false
        }
    }

    pub fn win(&self, password: &str, time_elapsed: Option<u128>) {
        push_message(
            Type::Success,
            &format!("{} :: ", &self.filepath.red())
        );

        println!("{}", password.bold().yellow());

        if let Some(time_elapsed) = time_elapsed {
            push_message(
                Type::Info,
                "Cracked in "
            );
            eprintln!("{} milliseconds", time_elapsed);
        }

        process::exit(0)
    }

    pub fn crack(&self) {
        Self::sanity_check(&self);

        push_message(
            Type::Info,
            &format!("PDF File: {}\n", &self.filepath.bold().red())
        );

        let pdf_file = match fs::read(&self.filepath) {
            Ok(bytes) => bytes,
            Err(_) => {
                push_message(
                    Type::Info,
                    "Failed to read the PDF file."
                );
                process::exit(1)
            }
        };

        if let Some(wordlist_path) = &self.wordlist_path {
            push_message(
                Type::Info,
                &format!("Wordlist File: {}\n\n", wordlist_path.bold().red())
            );

            let wordlist_bytes = match fs::read(wordlist_path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    push_message(
                        Type::Error,
                        &format!("Failed to read the wordlist file due to: {}", error)
                    );
                    process::exit(1)
                }
            };

            let wordlist = String::from_utf8_lossy(&wordlist_bytes);
    
            let progress_bar = ProgressBar::new(wordlist.matches('\n').count() as u64);

            wordlist.par_lines().for_each(|password| {
                if Self::decrypt_pdf(pdf_file.clone(), password.as_bytes()) {
                    Self::win(&self, password, None)
                }
                progress_bar.inc(1);
            });
    
            progress_bar.finish();
        }

        if let Some(num_bruteforce_range) = &self.num_bruteforce {
            let range = parsers::parse_range(num_bruteforce_range.to_owned());

            push_message(
                Type::Info,
                &format!("Number Bruteforce Mode: {} payloads\n\n", range.len().to_string().bold().red())
            );

            let progress_bar = ProgressBar::new(range.len() as u64);

            range.par_iter().for_each(|number| {
                if Self::decrypt_pdf(pdf_file.clone(), number.as_bytes()) {
                    Self::win(&self, number, None)
                }
                progress_bar.inc(1);
            });
    
            progress_bar.finish();
        }

        if let Some(date_bruteforce) = &self.date_bruteforce {
            let dates = parsers::construct_dates(date_bruteforce.to_owned());
    
            let mut report_progress = false;
            let progress_bar = ProgressBar::new(dates.len() as u64);
            if dates.len() > 10000 { report_progress = true }

            let cpu_time = std::time::Instant::now();

            dates.par_iter().for_each(|date| {
                if Self::decrypt_pdf(pdf_file.clone(), date.as_bytes()) {
                    Self::win(&self, date, Some(cpu_time.elapsed().as_millis()))
                }
                if report_progress {
                    progress_bar.inc(1);
                }
            });

            if report_progress {
                progress_bar.finish();
            }
        }

        if let Some(custom_query) = &self.custom_query {
            let queries = parsers::custom_query_parser(custom_query.to_owned());

            let mut report_progress = false;
            let progress_bar = ProgressBar::new(queries.len() as u64);
            if queries.len() > 10000 { report_progress = true }            
    
            push_message(
                Type::Info,
                &format!("Custom Query Mode: {} payloads\n\n", queries.len().to_string().bold().red())
            );

            let cpu_time = std::time::Instant::now();

            queries.par_iter().for_each(|query| {
                if Self::decrypt_pdf(pdf_file.clone(), query.as_bytes()) {
                    Self::win(&self, query, Some(cpu_time.elapsed().as_millis()))
                }
                if report_progress {
                    progress_bar.inc(1);
                }                
            });

            if report_progress {
                progress_bar.finish();
            }
        }

        eprintln!("\nNone of those were the password :(, try building a custom query with `-q` if you know the password format!");
    }

    pub fn sanity_check(&self) {
        if self.wordlist_path.is_none() &&
           self.num_bruteforce.is_none() &&
           self.date_bruteforce.is_none() &&
           self.custom_query.is_none()
        {
            push_message(
                Type::Error,
                "You have to use either `--wordlist` OR `--num-bruteforce` \
                OR `--date-bruteforce` OR `--custom-query` mode."
            );
            process::exit(1)
        }

        let mode_set = vec![
            self.wordlist_path.is_some(),
            self.num_bruteforce.is_some(),
            self.date_bruteforce.is_some(),
            self.custom_query.is_some()
        ];

        let mut c = 0;
        for mode in mode_set { if mode { c += 1 } }
        if c > 1 {
            push_message(
                Type::Error,
                "You can only use one mode at a time."
            );
            process::exit(1)
        }

        if !Path::new(&self.filepath).is_file() {
            push_message(
                Type::Error,
                &format!("The given PDF file `{}` does not exist", &self.filepath)
            );
            process::exit(1)
        }

        if let Some(wordlist_path) = &self.wordlist_path {
            if !Path::new(&wordlist_path).is_file() {
                push_message(
                    Type::Error,
                    &format!("The given wordlist file `{}` does not exist", &wordlist_path)
                );
                process::exit(1)
            }
        }

        match File::<Vec<u8>>::open_password(&self.filepath, b"dummytesttoomuchentropy12345") {
            Ok(_) => {
                push_message(
                    Type::Error,
                    "This PDF file is not encrypted."
                );
                process::exit(0)                
            },
            Err(error) => {
                if error.to_string().contains("crypt_filters") {
                    push_message(
                        Type::Error,
                        "This PDF encryption algorithm isn't supported yet. :("
                    );
                    process::exit(0)
                } else if error.to_string().contains("file header is missing") {
                    push_message(
                        Type::Error,
                        "Invalid PDF file."
                    );
                    process::exit(1)
                }
            }
        }
    }
}