use cli_interface::{arguments, entrypoint, Code};

#[test]
fn finds_mixed_uppercase_and_digit_masks() {
    let args = arguments::Arguments {
        number_of_threads: 2,
        batch_size: engine::default_batch_size(),
        filename: "crates/cracker/tests/fixtures/mask-upper-digit.pdf".to_string(),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::Mask(arguments::MaskArgs {
            mask: "?u{2}?d{2}".to_string(),
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");
    assert!(matches!(res, Code::Success), "Failed cracking file.")
}
