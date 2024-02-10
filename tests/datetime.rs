use cli_interface::{arguments, entrypoint, Code};

#[test]
fn success() {
    let args = arguments::Arguments {
        number_of_threads: 4,
        filename: "examples/datetime-15012000.pdf".to_string(),
        subcommand: arguments::Method::Date(arguments::DateArgs {
            start: 1999,
            end: 2000,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}
