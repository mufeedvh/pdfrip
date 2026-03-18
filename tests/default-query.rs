use cli_interface::{arguments, entrypoint, entrypoint_with_writer, Code};
use engine::CancellationToken;

fn fixture_path(name: &str) -> String {
    format!("crates/cracker/tests/fixtures/{name}")
}

#[test]
fn finds_single_lowercase_password() {
    let args = arguments::Arguments {
        number_of_threads: 2,
        batch_size: engine::default_batch_size(),
        filename: fixture_path("default-query-lower-a.pdf"),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 1,
            max_length: 1,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}

#[test]
fn finds_single_digit_password() {
    let args = arguments::Arguments {
        number_of_threads: 2,
        batch_size: engine::default_batch_size(),
        filename: fixture_path("default-query-digit-0.pdf"),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 1,
            max_length: 1,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}

#[test]
fn finds_single_space_password() {
    let args = arguments::Arguments {
        number_of_threads: 2,
        batch_size: engine::default_batch_size(),
        filename: fixture_path("default-query-space.pdf"),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 1,
            max_length: 1,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}

#[test]
fn historical_default_query_progress_regression_is_fixed_for_issues_40_41_and_61() {
    let args = arguments::Arguments {
        number_of_threads: 2,
        batch_size: engine::default_batch_size(),
        filename: fixture_path("mask-upper-digit.pdf"),
        json: true,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 1,
            max_length: 1,
        }),
    };

    let mut output = Vec::new();
    let res = entrypoint_with_writer(args, CancellationToken::new(), &mut output)
        .expect("regression run should complete cleanly");
    assert!(
        matches!(res, Code::Failure),
        "search should exhaust without a match"
    );

    let output = String::from_utf8(output).expect("json output should be valid utf-8");
    assert!(output.contains("\"status\":\"exhausted\""));
    assert!(output.contains("\"attempts\":95"));
    assert!(output.contains("\"total_candidates\":95"));
}
