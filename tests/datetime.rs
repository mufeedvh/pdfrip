use cli_interface::{arguments, entrypoint, Code};

#[test]
fn success() {
    let args = arguments::Arguments {
        number_of_threads: 4,
        batch_size: engine::default_batch_size(),
        filename: "examples/datetime-15012000.pdf".to_string(),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::Date(arguments::DateArgs {
            format: "DDMMYYYY".to_string(),
            start: 1999,
            end: 2000,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}

#[test]
fn supports_configurable_date_formats() {
    let args = arguments::Arguments {
        number_of_threads: 4,
        batch_size: engine::default_batch_size(),
        filename: "crates/cracker/tests/fixtures/date-dot-format.pdf".to_string(),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::Date(arguments::DateArgs {
            format: "DD.MM.YYYY".to_string(),
            start: 2000,
            end: 2000,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}
