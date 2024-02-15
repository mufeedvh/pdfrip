use cli_interface::{arguments, entrypoint, Code};

#[test]
#[ignore = "This is slow"]
fn success_pdf1() {
    let args = arguments::Arguments {
        number_of_threads: 4,
        filename: "examples/default-query-1.pdf".to_string(),
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 4,
            max_length: 4,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}

#[test]
#[ignore = "This is slow"]
fn success_pdf2() {
    let args = arguments::Arguments {
        number_of_threads: 4,
        filename: "examples/default-query-2.pdf".to_string(),
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 4,
            max_length: 4,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}
