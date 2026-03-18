use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use cli_interface::{arguments, entrypoint_with_writer, Code};
use engine::CancellationToken;

fn temp_wordlist_path(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!("pdfrip-{name}-{}-{unique}.txt", std::process::id()))
}

#[test]
fn human_output_makes_blank_user_passwords_explicit() {
    let args = arguments::Arguments {
        number_of_threads: 1,
        batch_size: 8,
        filename: "crates/cracker/tests/fixtures/r4-aes128-blank-user.pdf".to_string(),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 0,
            max_length: 0,
        }),
    };

    let mut output = Vec::new();
    let code = entrypoint_with_writer(args, CancellationToken::new(), &mut output)
        .expect("blank-password crack should complete cleanly");

    assert!(matches!(code, Code::Success));
    let output = String::from_utf8(output).expect("output should be valid utf-8");
    assert!(output.contains("Success: found blank user password \"\"."));
}

#[test]
fn wordlist_blank_lines_can_represent_blank_passwords() {
    let wordlist = temp_wordlist_path("blank-password");
    std::fs::write(&wordlist, b"\n").expect("wordlist should be writable");

    let args = arguments::Arguments {
        number_of_threads: 1,
        batch_size: 8,
        filename: "crates/cracker/tests/fixtures/r4-aes128-blank-user.pdf".to_string(),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::Wordlist(arguments::DictionaryArgs {
            wordlist: wordlist.display().to_string(),
        }),
    };

    let mut output = Vec::new();
    let code = entrypoint_with_writer(args, CancellationToken::new(), &mut output)
        .expect("blank-password wordlist crack should complete cleanly");
    std::fs::remove_file(&wordlist).expect("temporary wordlist should be removable");

    assert!(matches!(code, Code::Success));
    let output = String::from_utf8(output).expect("output should be valid utf-8");
    assert!(output.contains("Success: found blank user password \"\"."));
}

#[test]
fn human_output_reports_owner_password_matches_in_default_mode() {
    let wordlist = temp_wordlist_path("owner-password");
    std::fs::write(&wordlist, b"owner-blank\n").expect("wordlist should be writable");

    let args = arguments::Arguments {
        number_of_threads: 1,
        batch_size: 8,
        filename: "crates/cracker/tests/fixtures/r4-aes128-blank-user.pdf".to_string(),
        json: false,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::Wordlist(arguments::DictionaryArgs {
            wordlist: wordlist.display().to_string(),
        }),
    };

    let mut output = Vec::new();
    let code = entrypoint_with_writer(args, CancellationToken::new(), &mut output)
        .expect("owner-password crack should complete cleanly");
    std::fs::remove_file(&wordlist).expect("temporary wordlist should be removable");

    assert!(matches!(code, Code::Success));
    let output = String::from_utf8(output).expect("output should be valid utf-8");
    assert!(output.contains("Success: found owner password \"owner-blank\"."));
}

#[test]
fn human_output_user_only_mode_rejects_owner_only_matches() {
    let wordlist = temp_wordlist_path("owner-password-user-only");
    std::fs::write(&wordlist, b"owner-blank\n").expect("wordlist should be writable");

    let args = arguments::Arguments {
        number_of_threads: 1,
        batch_size: 8,
        filename: "crates/cracker/tests/fixtures/r4-aes128-blank-user.pdf".to_string(),
        json: false,
        user_password_only: true,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::Wordlist(arguments::DictionaryArgs {
            wordlist: wordlist.display().to_string(),
        }),
    };

    let mut output = Vec::new();
    let code = entrypoint_with_writer(args, CancellationToken::new(), &mut output)
        .expect("user-only crack should complete cleanly");
    std::fs::remove_file(&wordlist).expect("temporary wordlist should be removable");

    assert!(matches!(code, Code::Failure));
    let output = String::from_utf8(output).expect("output should be valid utf-8");
    assert!(output.contains("Completed search without finding a matching password."));
    assert!(!output.contains("Success: found owner password \"owner-blank\"."));
}

#[test]
fn json_output_marks_blank_password_kind_and_representation() {
    let args = arguments::Arguments {
        number_of_threads: 1,
        batch_size: 8,
        filename: "crates/cracker/tests/fixtures/r4-aes128-blank-user.pdf".to_string(),
        json: true,
        user_password_only: false,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 0,
            max_length: 0,
        }),
    };

    let mut output = Vec::new();
    let code = entrypoint_with_writer(args, CancellationToken::new(), &mut output)
        .expect("blank-password JSON run should complete cleanly");

    assert!(matches!(code, Code::Success));
    let output = String::from_utf8(output).expect("output should be valid utf-8");
    assert!(output.contains("\"status\":\"success\""));
    assert!(output.contains("\"password_kind\":\"user\""));
    assert!(output.contains("\"kind\":\"blank\""));
    assert!(output.contains("\"display\":\"\\\"\\\"\""));
}

#[test]
fn json_output_user_only_mode_still_reports_user_passwords_as_user() {
    let args = arguments::Arguments {
        number_of_threads: 1,
        batch_size: 8,
        filename: "crates/cracker/tests/fixtures/r4-aes128-blank-user.pdf".to_string(),
        json: true,
        user_password_only: true,
        checkpoint: None,
        resume: None,
        subcommand: arguments::Method::DefaultQuery(arguments::DefaultQueryArgs {
            min_length: 0,
            max_length: 0,
        }),
    };

    let mut output = Vec::new();
    let code = entrypoint_with_writer(args, CancellationToken::new(), &mut output)
        .expect("user-only JSON run should complete cleanly");

    assert!(matches!(code, Code::Success));
    let output = String::from_utf8(output).expect("output should be valid utf-8");
    assert!(output.contains("\"status\":\"success\""));
    assert!(output.contains("\"password_kind\":\"user\""));
    assert!(output.contains("\"kind\":\"blank\""));
}
