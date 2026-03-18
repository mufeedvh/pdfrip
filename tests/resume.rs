use std::{
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cli_interface::{arguments, entrypoint_with_writer, Code};
use engine::CancellationToken;

fn temp_checkpoint_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "pdfrip-resume-{}-{unique}.json",
        std::process::id()
    ))
}

#[test]
fn checkpointed_runs_can_resume_to_completion() {
    let checkpoint = temp_checkpoint_path();
    let mut cancelled_output = Vec::new();
    let cancellation = CancellationToken::new();
    let cancellation_for_thread = cancellation.clone();

    let cancel_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        cancellation_for_thread.cancel();
    });

    let cancelled_args = arguments::Arguments {
        number_of_threads: 1,
        batch_size: 32,
        filename: "crates/cracker/tests/fixtures/resume-late-mask.pdf".to_string(),
        json: true,
        user_password_only: false,
        checkpoint: Some(checkpoint.clone()),
        resume: None,
        subcommand: arguments::Method::Mask(arguments::MaskArgs {
            mask: "?u?d{2}".to_string(),
        }),
    };

    let cancelled_code =
        entrypoint_with_writer(cancelled_args, cancellation, &mut cancelled_output)
            .expect("cancelled run should finish cleanly");
    cancel_thread
        .join()
        .expect("cancel thread should join cleanly");
    assert!(matches!(cancelled_code, Code::Cancelled));
    assert!(checkpoint.exists(), "checkpoint file should be created");

    let mut resumed_output = Vec::new();
    let resumed_args = arguments::Arguments {
        number_of_threads: 1,
        batch_size: 32,
        filename: "crates/cracker/tests/fixtures/resume-late-mask.pdf".to_string(),
        json: true,
        user_password_only: false,
        checkpoint: Some(checkpoint.clone()),
        resume: Some(checkpoint.clone()),
        subcommand: arguments::Method::Mask(arguments::MaskArgs {
            mask: "?u?d{2}".to_string(),
        }),
    };

    let resumed_code =
        entrypoint_with_writer(resumed_args, CancellationToken::new(), &mut resumed_output)
            .expect("resumed run should finish cleanly");
    assert!(matches!(resumed_code, Code::Success));

    let payload = String::from_utf8(resumed_output).expect("resumed output should be valid utf-8");
    assert!(payload.contains("\"status\":\"success\""));
    assert!(payload.contains("\"display\":\"\\\"Z99\\\"\""));
    assert!(payload.contains("\"password_kind\":\"user\""));

    if checkpoint.exists() {
        std::fs::remove_file(checkpoint).expect("checkpoint should be removable after the test");
    }
}
