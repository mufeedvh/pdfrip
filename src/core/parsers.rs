use std::process;

use crate::cli::messages::{
    Type, push_message
};

use crate::cli::interface;

/// Number range parser
/// 
/// Parses "69-420" queries and populates a vector with the whole range.
pub fn parse_range(range_input: String) -> Vec<String> {
    fn format_error() {
        push_message(
            Type::Error,
            "Invalid range format. (Use format: `-n 1337-13337`)"
        );
    }

    let mut next_range = false;
    let mut start_range = String::new();
    let mut end_range = String::new();

    for c in range_input.chars() {
        match c {
            '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | '0' => {
                if !next_range {
                    start_range.push(c)
                } else {
                    end_range.push(c)
                }
            },
            '-' => {
                if !next_range {
                    next_range = true;
                }
            },
            _ => {
                format_error();
                process::exit(1)
            }
        }
    }

    if !next_range {
        format_error();
        process::exit(1)
    }

    let start_range = match start_range.parse::<usize>() {
        Ok(num) => num,
        Err(_) => {
            format_error();
            process::exit(1)
        }
    };

    let end_range = match end_range.parse::<usize>() {
        Ok(num) => num,
        Err(_) => {
            format_error();
            process::exit(1)
        }
    };

    let range: Vec<usize> = (start_range..(end_range + 1)).collect();

    let mut wordlist: Vec<String> = Vec::with_capacity(range.len());

    for num in range {
        wordlist.push(num.to_string())
    }

    wordlist
}


/// Constructs a 365 day wordlist of the input year in DDMMYYYY format
pub fn construct_dates(year: String) -> Vec<String> {
    let mut dates_wordlist: Vec<String> = Vec::new();

    let dates: Vec<usize> = (1..32).collect();
    let months: Vec<usize> = (1..13).collect();

    for month in months {
        for date in &dates {
            let date: String = if date < &10 {
                format!("0{}", date)
            } else {
                date.to_string()
            };

            let month: String = if month < 10 {
                format!("0{}", month)
            } else {
                month.to_string()
            };

            dates_wordlist.push(
                format!("{}{}{}", date, month, year)
            )
        }
    }

    dates_wordlist
}


/// Custom query parser
/// 
/// Parses queries like "ALICE{1000-5000}BOB" and populates a vector with
/// the whole range.
pub fn custom_query_parser(query: String) -> Vec<String> {
    fn format_error() {
        push_message(
            Type::Error,
            "Invalid custom query format. (Use format: `-q STRING{1337-13337}`)"
        );
    }

    if query.matches('{').count() > 1 {
        format_error();
        process::exit(1)
    }

    let mut start_parse = false;
    let mut end_parse = false;
    let mut next_range = false;
    let mut start_range = String::new();
    let mut end_range = String::new();

    let mut prefix = String::new();
    let mut range_enclave = String::new();
    let mut suffix = String::new();

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
            },
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
            },
            '{' => {
                start_parse = true;
                range_enclave.push(c)
            },
            '}' => {
                end_parse = true;
                range_enclave.push(c)
            },
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

    let end_num_digits = end_range.len();

    let start_range = match start_range.parse::<usize>() {
        Ok(num) => num,
        Err(_) => {
            format_error();
            process::exit(1)
        }
    };

    let end_range = match end_range.parse::<usize>() {
        Ok(num) => num,
        Err(_) => {
            format_error();
            process::exit(1)
        }
    };

    let range: Vec<usize> = (start_range..(end_range + 1)).collect();

    let mut wordlist: Vec<String> = Vec::with_capacity(range.len());

    let preceding_zeros_enabled = interface::args().is_present("add_preceding_zeros");

    for num in range {
        let mut num = num.to_string();

        if preceding_zeros_enabled {
            if num.len() < end_num_digits {
                num = format!("{}{}", "0".repeat(end_num_digits - num.len()), num);
            }
        }
        
        wordlist.push(
            format!("{}{}{}", prefix, num, suffix)
        )
    }
    
    wordlist
}