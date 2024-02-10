use cli_interface::{arguments, entrypoint, Code};

#[test]
fn successful_crack() {
    let args = arguments::Arguments {
        number_of_threads: 4,
        filename: "examples/ALICE_BANK_STATEMENT.pdf".to_string(),
        subcommand: arguments::Method::CustomQuery(arguments::CustomQueryArgs {
            custom_query: "ALICE{1-9999}".to_string(),
            add_preceding_zeros: true,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}

#[test]
fn failed_crack() {
    let args = arguments::Arguments {
        number_of_threads: 4,
        filename: "examples/ALICE_BANK_STATEMENT.pdf".to_string(),
        subcommand: arguments::Method::CustomQuery(arguments::CustomQueryArgs {
            custom_query: "IM_BATMAN{1-2}".to_string(),
            add_preceding_zeros: true,
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");
    assert!(matches!(res, Code::Failure), "We expected to fail this.")
}
