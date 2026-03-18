use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use cli_interface::{arguments, entrypoint, Code};

fn temp_wordlist() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "pdfrip-contains-word-{}-{unique}.txt",
        std::process::id()
    ))
}

#[test]
fn finds_candidates_that_contain_the_required_word() {
    let path = temp_wordlist();
    std::fs::write(&path, b"ALICE\n").expect("wordlist should be writable");

    let args = arguments::Arguments {
        number_of_threads: 2,
        batch_size: engine::default_batch_size(),
        filename: "crates/cracker/tests/fixtures/contains-word-alice.pdf".to_string(),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::ContainsWord(arguments::ContainsWordArgs {
            wordlist: path.display().to_string(),
            min_length: 7,
            max_length: 7,
            fill_charset: "digit".to_string(),
        }),
    };

    let res = entrypoint(args).expect("An error occured when cracking file");
    std::fs::remove_file(&path).expect("temporary wordlist should be removable");

    assert!(matches!(res, Code::Success), "Failed cracking file.")
}
