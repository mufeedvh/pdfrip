//! User-facing CLI orchestration for `pdfrip`.
//!
//! This crate owns argument parsing, progress-bar rendering, checkpoint persistence, and final
//! output formatting. The engine stays responsible for actual work coordination, while this layer
//! translates engine results into human-readable or JSON responses.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context};
use arguments::{Arguments, JobDefinition, Method};
use engine::{
    crackers::{PDFCracker, PasswordKind},
    producers::{
        contains_word::{ContainsWordProducer, FillCharset},
        custom_query::CustomQuery,
        dates::DateProducer,
        default_query::DefaultQuery,
        dictionary::LineProducer,
        mask::MaskProducer,
        number_ranges::RangeProducer,
        Producer,
    },
    CancellationToken, JobOptions, JobResult, JobStatus, ProgressUpdate,
};
use indicatif::{ProgressBar, ProgressStyle};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Contains the argument parser.
pub mod arguments;

mod banner;

const CHECKPOINT_VERSION: u32 = 2;

/// Process exit classification used by the binary entrypoint.
pub enum Code {
    Success,
    Failure,
    Cancelled,
}

/// Re-export our result type instead of defining a custom error wrapper.
pub type Result = anyhow::Result<Code>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CheckpointFile {
    version: u32,
    saved_at_unix_ms: u128,
    job: JobDefinition,
    job_fingerprint: String,
    total_candidates: usize,
    verified_attempts: usize,
}

#[derive(Debug, Clone)]
struct CheckpointMetadata {
    path: PathBuf,
    verified_attempts: usize,
    total_candidates: usize,
    resumed: bool,
    saved: bool,
    cleared: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PasswordRole {
    User,
    Owner,
}

impl From<PasswordKind> for PasswordRole {
    fn from(value: PasswordKind) -> Self {
        match value {
            PasswordKind::User => Self::User,
            PasswordKind::Owner => Self::Owner,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PasswordRenderKind {
    Blank,
    Utf8,
    Bytes,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RenderedPassword {
    kind: PasswordRenderKind,
    display: String,
    utf8: Option<String>,
    hex: String,
}

#[derive(Debug, Serialize)]
struct JsonCheckpoint<'a> {
    path: String,
    verified_attempts: usize,
    total_candidates: usize,
    resumed: bool,
    saved: bool,
    cleared: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct JsonSummary<'a> {
    status: &'a str,
    attempts: usize,
    total_candidates: usize,
    elapsed_seconds: f64,
    throughput_per_second: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<RenderedPassword>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_kind: Option<PasswordRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resumed_from_attempt: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint: Option<JsonCheckpoint<'a>>,
}

fn digit_width(value: usize) -> usize {
    value
        .checked_ilog10()
        .map(|digits| digits as usize + 1)
        .unwrap_or(1)
}

fn select_producer(subcommand: Method) -> anyhow::Result<Box<dyn Producer>> {
    let producer: Box<dyn Producer> = match subcommand {
        Method::Wordlist(args) => {
            Box::from(LineProducer::try_from_path(&args.wordlist).map_err(anyhow::Error::msg)?)
        }
        Method::Range(args) => {
            let padding = if args.add_preceding_zeros {
                digit_width(args.upper_bound)
            } else {
                0
            };
            Box::from(
                RangeProducer::try_new(padding, args.lower_bound, args.upper_bound)
                    .map_err(anyhow::Error::msg)?,
            )
        }
        Method::CustomQuery(args) => Box::from(
            CustomQuery::try_new(&args.custom_query, args.add_preceding_zeros)
                .map_err(anyhow::Error::msg)?,
        ),
        Method::Mask(args) => {
            Box::from(MaskProducer::try_new(&args.mask).map_err(anyhow::Error::msg)?)
        }
        Method::ContainsWord(args) => Box::from(
            ContainsWordProducer::try_new(
                &args.wordlist,
                args.min_length,
                args.max_length,
                FillCharset::from_name(&args.fill_charset).map_err(anyhow::Error::msg)?,
            )
            .map_err(anyhow::Error::msg)?,
        ),
        Method::Date(args) => Box::from(
            DateProducer::try_new_with_format(args.start, args.end, &args.format)
                .map_err(anyhow::Error::msg)?,
        ),
        Method::DefaultQuery(args) => Box::from(
            DefaultQuery::try_new(args.max_length, args.min_length).map_err(anyhow::Error::msg)?,
        ),
    };

    Ok(producer)
}

fn create_progress_bar(
    total_candidates: usize,
    initial_attempts: usize,
) -> anyhow::Result<ProgressBar> {
    let progress_bar = ProgressBar::new(total_candidates as u64);
    progress_bar.set_position(initial_attempts as u64);
    progress_bar.set_style(ProgressStyle::default_bar().template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {percent}% {per_sec} ETA: {eta}",
    )?);
    Ok(progress_bar)
}

fn render_password(password: &[u8]) -> RenderedPassword {
    let hex = password
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");

    if password.is_empty() {
        return RenderedPassword {
            kind: PasswordRenderKind::Blank,
            display: String::from("\"\""),
            utf8: Some(String::new()),
            hex,
        };
    }

    match std::str::from_utf8(password) {
        Ok(value) => RenderedPassword {
            kind: PasswordRenderKind::Utf8,
            display: serde_json::to_string(value).expect("serializing utf-8 password should work"),
            utf8: Some(value.to_string()),
            hex,
        },
        Err(_) => RenderedPassword {
            kind: PasswordRenderKind::Bytes,
            display: hex.clone(),
            utf8: None,
            hex,
        },
    }
}

fn elapsed_seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

fn throughput(attempts: usize, duration: Duration) -> f64 {
    let seconds = elapsed_seconds(duration);
    if seconds == 0.0 {
        attempts as f64
    } else {
        attempts as f64 / seconds
    }
}

fn format_seconds(duration: Duration) -> String {
    format!("{:.2}s", elapsed_seconds(duration))
}

fn checkpoint_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_millis()
}

fn compute_job_fingerprint(args: &Arguments) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    let serialized_job = serde_json::to_vec(&args.job_definition())
        .context("failed to serialize job definition for checkpoint fingerprinting")?;
    hasher.update(serialized_job);

    let pdf_bytes = fs::read(&args.filename).with_context(|| {
        format!(
            "unable to read PDF file '{}' for checkpoint validation",
            args.filename
        )
    })?;
    hasher.update(pdf_bytes);

    if let Method::Wordlist(dictionary) = &args.subcommand {
        let wordlist_bytes = fs::read(&dictionary.wordlist).with_context(|| {
            format!(
                "unable to read wordlist '{}' for checkpoint validation",
                dictionary.wordlist
            )
        })?;
        hasher.update(wordlist_bytes);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn load_checkpoint(
    path: &Path,
    job: &JobDefinition,
    job_fingerprint: &str,
    total_candidates: usize,
) -> anyhow::Result<CheckpointFile> {
    let bytes = fs::read(path)
        .with_context(|| format!("unable to read checkpoint file '{}'", path.display()))?;
    let checkpoint: CheckpointFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("checkpoint '{}' is not valid JSON", path.display()))?;

    if checkpoint.version != CHECKPOINT_VERSION {
        return Err(anyhow!(
            "checkpoint '{}' uses unsupported version {}",
            path.display(),
            checkpoint.version
        ));
    }
    if checkpoint.job != *job {
        return Err(anyhow!(
            "checkpoint '{}' does not match the current PDF path and cracking method",
            path.display()
        ));
    }
    if checkpoint.job_fingerprint != job_fingerprint {
        return Err(anyhow!(
            "checkpoint '{}' does not match the current input files",
            path.display()
        ));
    }
    if checkpoint.total_candidates != total_candidates {
        return Err(anyhow!(
            "checkpoint '{}' was created for a different candidate count ({} != {})",
            path.display(),
            checkpoint.total_candidates,
            total_candidates
        ));
    }
    if checkpoint.verified_attempts > checkpoint.total_candidates {
        return Err(anyhow!(
            "checkpoint '{}' is corrupt: verified attempts exceed total candidates",
            path.display()
        ));
    }

    Ok(checkpoint)
}

fn save_checkpoint(path: &Path, checkpoint: &CheckpointFile) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "unable to create checkpoint directory '{}'",
                parent.display()
            )
        })?;
    }

    let temp_path = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("json"),
        std::process::id()
    ));
    let bytes =
        serde_json::to_vec_pretty(checkpoint).context("failed to serialize checkpoint as JSON")?;

    fs::write(&temp_path, bytes).with_context(|| {
        format!(
            "unable to write temporary checkpoint file '{}'",
            temp_path.display()
        )
    })?;

    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("unable to replace checkpoint file '{}'", path.display()))?;
    }

    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "unable to move temporary checkpoint '{}' into place as '{}'",
            temp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

fn clear_checkpoint(path: &Path) -> bool {
    match fs::remove_file(path) {
        Ok(()) => {
            info!("event=checkpoint_cleared path={}", path.display());
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            warn!(
                "event=checkpoint_clear_failed path={} error={}",
                path.display(),
                error
            );
            false
        }
    }
}

fn finalize_checkpoint(
    args: &Arguments,
    job: &JobDefinition,
    job_fingerprint: &str,
    total_candidates: usize,
    result: &JobResult,
    resumed_from: usize,
) -> anyhow::Result<Option<CheckpointMetadata>> {
    let checkpoint_path = args.checkpoint_output_path();

    match result.status {
        JobStatus::Cancelled => {
            let Some(path) = checkpoint_path else {
                return Ok(None);
            };

            let checkpoint = CheckpointFile {
                version: CHECKPOINT_VERSION,
                saved_at_unix_ms: checkpoint_timestamp(),
                job: job.clone(),
                job_fingerprint: job_fingerprint.to_string(),
                total_candidates,
                verified_attempts: result.attempts,
            };
            save_checkpoint(&path, &checkpoint)?;
            info!(
                "event=checkpoint_saved path={} verified_attempts={} total_candidates={}",
                path.display(),
                result.attempts,
                total_candidates
            );
            Ok(Some(CheckpointMetadata {
                path,
                verified_attempts: result.attempts,
                total_candidates,
                resumed: resumed_from > 0,
                saved: true,
                cleared: false,
            }))
        }
        JobStatus::Success | JobStatus::Exhausted => {
            if let Some(path) = checkpoint_path {
                let cleared = clear_checkpoint(&path);
                return Ok(Some(CheckpointMetadata {
                    path,
                    verified_attempts: result.attempts,
                    total_candidates,
                    resumed: resumed_from > 0,
                    saved: false,
                    cleared,
                }));
            }

            if resumed_from > 0 {
                return Ok(Some(CheckpointMetadata {
                    path: args
                        .resume
                        .clone()
                        .unwrap_or_else(|| PathBuf::from("<checkpoint>")),
                    verified_attempts: result.attempts,
                    total_candidates,
                    resumed: true,
                    saved: false,
                    cleared: false,
                }));
            }

            Ok(None)
        }
    }
}

fn write_human_summary<W: Write>(
    writer: &mut W,
    result: &JobResult,
    password_kind: Option<PasswordKind>,
    elapsed: Duration,
    checkpoint: Option<&CheckpointMetadata>,
) -> anyhow::Result<()> {
    let rendered_password = result.password.as_deref().map(render_password);

    match result.status {
        JobStatus::Success => {
            let password = rendered_password
                .as_ref()
                .expect("successful runs should include a password");
            let role_prefix = match password_kind {
                Some(PasswordKind::User) => "user ",
                Some(PasswordKind::Owner) => "owner ",
                None => "",
            };
            match password.kind {
                PasswordRenderKind::Blank => {
                    writeln!(
                        writer,
                        "Success: found blank {role_prefix}password {}.",
                        password.display
                    )?;
                }
                PasswordRenderKind::Utf8 => {
                    writeln!(
                        writer,
                        "Success: found {role_prefix}password {}.",
                        password.display
                    )?;
                }
                PasswordRenderKind::Bytes => {
                    writeln!(
                        writer,
                        "Success: found a non-UTF-8 {role_prefix}password with raw bytes {}.",
                        password.display
                    )?;
                }
            }
        }
        JobStatus::Exhausted => {
            writeln!(
                writer,
                "Completed search without finding a matching password."
            )?;
        }
        JobStatus::Cancelled => {
            writeln!(writer, "Cancelled after draining already queued work.")?;
        }
    }

    if result.resumed_from > 0 {
        writeln!(
            writer,
            "Resumed from verified attempt {}.",
            result.resumed_from
        )?;
    }

    if let Some(checkpoint) = checkpoint {
        if checkpoint.saved {
            writeln!(
                writer,
                "Checkpoint saved to '{}' at attempt {}/{}.",
                checkpoint.path.display(),
                checkpoint.verified_attempts,
                checkpoint.total_candidates
            )?;
        } else if checkpoint.cleared {
            writeln!(
                writer,
                "Checkpoint '{}' cleared.",
                checkpoint.path.display()
            )?;
        }
    }

    writeln!(
        writer,
        "Attempts: {}/{}",
        result.attempts, result.total_candidates
    )?;
    writeln!(writer, "Elapsed: {}", format_seconds(elapsed))?;
    writeln!(
        writer,
        "Throughput: {:.2} attempts/s",
        throughput(result.attempts, elapsed)
    )?;

    Ok(())
}

fn write_json_summary<W: Write>(
    writer: &mut W,
    result: &JobResult,
    password_kind: Option<PasswordKind>,
    elapsed: Duration,
    checkpoint: Option<&CheckpointMetadata>,
) -> anyhow::Result<()> {
    let summary = JsonSummary {
        status: match result.status {
            JobStatus::Success => "success",
            JobStatus::Exhausted => "exhausted",
            JobStatus::Cancelled => "cancelled",
        },
        attempts: result.attempts,
        total_candidates: result.total_candidates,
        elapsed_seconds: elapsed_seconds(elapsed),
        throughput_per_second: throughput(result.attempts, elapsed),
        password: result.password.as_deref().map(render_password),
        password_kind: password_kind.map(PasswordRole::from),
        resumed_from_attempt: (result.resumed_from > 0).then_some(result.resumed_from),
        checkpoint: checkpoint.map(|checkpoint| JsonCheckpoint {
            path: checkpoint.path.display().to_string(),
            verified_attempts: checkpoint.verified_attempts,
            total_candidates: checkpoint.total_candidates,
            resumed: checkpoint.resumed,
            saved: checkpoint.saved,
            cleared: checkpoint.cleared,
            note: if checkpoint.saved {
                Some("resume from this checkpoint by re-running the same job with --resume <path>")
            } else {
                None
            },
        }),
    };

    serde_json::to_writer(&mut *writer, &summary).context("failed to serialize JSON output")?;
    writeln!(writer)?;
    Ok(())
}

/// Runs the CLI with a fresh, uncancelled token and writes output to stdout.
pub fn entrypoint(args: Arguments) -> Result {
    entrypoint_with_cancellation(args, CancellationToken::new())
}

/// Runs the CLI with an externally controlled cancellation token.
pub fn entrypoint_with_cancellation(args: Arguments, cancellation: CancellationToken) -> Result {
    let mut stdout = io::stdout().lock();
    entrypoint_with_writer(args, cancellation, &mut stdout)
}

/// Runs the CLI and writes the final user-facing output to the provided writer.
///
/// This function is primarily exposed so tests can capture human or JSON output without spawning
/// the full binary.
pub fn entrypoint_with_writer<W: Write>(
    args: Arguments,
    cancellation: CancellationToken,
    writer: &mut W,
) -> Result {
    if !args.json {
        banner::write_banner(writer).context("failed to write banner")?;
    }

    let producer = select_producer(args.subcommand.clone())?;
    let total_candidates = producer.size();
    let job_definition = args.job_definition();
    let job_fingerprint = compute_job_fingerprint(&args)?;

    let resumed_from = match args.resume.as_deref() {
        Some(path) => {
            load_checkpoint(path, &job_definition, &job_fingerprint, total_candidates)?
                .verified_attempts
        }
        None => 0,
    };

    if resumed_from > 0 {
        let resume_path = args
            .resume
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        info!(
            "event=checkpoint_loaded attempts={} total_candidates={} path={}",
            resumed_from, total_candidates, resume_path
        );
    }

    let progress_bar = if args.json {
        None
    } else {
        Some(create_progress_bar(total_candidates, resumed_from)?)
    };
    let progress_bar_for_callback = progress_bar.clone();
    let progress = move |update: ProgressUpdate| {
        if let Some(bar) = &progress_bar_for_callback {
            bar.set_position(update.attempts as u64);
        }
    };
    let progress_callback = if progress_bar.is_some() {
        Some(&progress as &dyn Fn(ProgressUpdate))
    } else {
        None
    };

    let filename = args.filename.clone();
    let cracker = PDFCracker::from_file_with_mode(&filename, args.verification_mode())
        .context(format!("path: {filename}"))?;

    let mut options = JobOptions::new(args.number_of_threads);
    options.batch_size = args.batch_size;
    options.initial_attempts = resumed_from;
    options.cancellation_token = cancellation;

    let started_at = Instant::now();
    let result =
        engine::crack_file_with_options(cracker.clone(), producer, options, progress_callback)?;
    let elapsed = started_at.elapsed();
    let password_kind = result
        .password
        .as_deref()
        .map(|password| cracker.classify_password(password))
        .transpose()?
        .flatten();

    if let Some(bar) = &progress_bar {
        bar.set_position(result.attempts as u64);
        bar.finish_and_clear();
    }

    let checkpoint = finalize_checkpoint(
        &args,
        &job_definition,
        &job_fingerprint,
        total_candidates,
        &result,
        resumed_from,
    )?;

    if args.json {
        write_json_summary(writer, &result, password_kind, elapsed, checkpoint.as_ref())?;
    } else {
        write_human_summary(writer, &result, password_kind, elapsed, checkpoint.as_ref())?;
    }

    Ok(match result.status {
        JobStatus::Success => Code::Success,
        JobStatus::Exhausted => Code::Failure,
        JobStatus::Cancelled => Code::Cancelled,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        arguments, entrypoint, entrypoint_with_writer, load_checkpoint, render_password,
        CancellationToken, CheckpointFile, CHECKPOINT_VERSION,
    };
    use crate::arguments::JobDefinition;
    use engine::crackers::VerificationMode;

    fn temp_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pdfrip-{name}-{}-{unique}.json",
            std::process::id()
        ))
    }

    fn workspace_path(relative: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
            .display()
            .to_string()
    }

    #[test]
    fn missing_wordlist_returns_a_normal_error() {
        let result = entrypoint(arguments::Arguments {
            number_of_threads: 1,
            batch_size: engine::default_batch_size(),
            filename: workspace_path("examples/ALICE_BANK_STATEMENT.pdf"),
            json: false,
            user_password_only: false,
            checkpoint: None,
            resume: None,
            subcommand: arguments::Method::Wordlist(arguments::DictionaryArgs {
                wordlist: workspace_path("examples/does-not-exist.txt"),
            }),
        });

        let error = match result {
            Ok(_) => panic!("missing wordlist should fail normally"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("Unable to read wordlist file"));
    }

    #[test]
    fn malformed_custom_query_returns_a_normal_error() {
        let result = entrypoint(arguments::Arguments {
            number_of_threads: 1,
            batch_size: engine::default_batch_size(),
            filename: workspace_path("examples/ALICE_BANK_STATEMENT.pdf"),
            json: false,
            user_password_only: false,
            checkpoint: None,
            resume: None,
            subcommand: arguments::Method::CustomQuery(arguments::CustomQueryArgs {
                custom_query: "ALICE{".to_string(),
                add_preceding_zeros: false,
            }),
        });

        let error = match result {
            Ok(_) => panic!("malformed query should fail normally"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("balanced braces"));
    }

    #[test]
    fn render_password_distinguishes_blank_utf8_and_raw_bytes() {
        let blank = render_password(b"");
        assert_eq!(blank.display, "\"\"");
        assert_eq!(blank.utf8.as_deref(), Some(""));

        let utf8 = render_password(b"hello world");
        assert_eq!(utf8.display, "\"hello world\"");
        assert_eq!(utf8.utf8.as_deref(), Some("hello world"));

        let bytes = render_password(&[0xff, 0x00]);
        assert_eq!(bytes.display, "ff 00");
        assert!(bytes.utf8.is_none());
    }

    #[test]
    fn checkpoint_loader_rejects_mismatched_jobs() {
        let path = temp_path("checkpoint-mismatch");
        let checkpoint = CheckpointFile {
            version: CHECKPOINT_VERSION,
            saved_at_unix_ms: 0,
            job: JobDefinition {
                filename: workspace_path("examples/ALICE_BANK_STATEMENT.pdf"),
                method: arguments::Method::Range(arguments::RangeArgs {
                    add_preceding_zeros: false,
                    lower_bound: 1,
                    upper_bound: 2,
                }),
                verification_mode: VerificationMode::default(),
            },
            job_fingerprint: String::from("test"),
            total_candidates: 2,
            verified_attempts: 1,
        };
        std::fs::write(&path, serde_json::to_vec(&checkpoint).unwrap())
            .expect("checkpoint should be writable");

        let result = load_checkpoint(
            &path,
            &JobDefinition {
                filename: workspace_path("examples/ALICE_BANK_STATEMENT.pdf"),
                method: arguments::Method::Range(arguments::RangeArgs {
                    add_preceding_zeros: false,
                    lower_bound: 9,
                    upper_bound: 10,
                }),
                verification_mode: VerificationMode::default(),
            },
            "test",
            2,
        );

        let error = result.expect_err("mismatched checkpoint should fail");
        assert!(error.to_string().contains("does not match"));
        std::fs::remove_file(path).expect("checkpoint should be removable");
    }

    #[test]
    fn checkpoint_loader_rejects_mismatched_verification_modes() {
        let path = temp_path("checkpoint-mode-mismatch");
        let checkpoint = CheckpointFile {
            version: CHECKPOINT_VERSION,
            saved_at_unix_ms: 0,
            job: JobDefinition {
                filename: workspace_path("examples/ALICE_BANK_STATEMENT.pdf"),
                method: arguments::Method::Range(arguments::RangeArgs {
                    add_preceding_zeros: false,
                    lower_bound: 1,
                    upper_bound: 2,
                }),
                verification_mode: VerificationMode::UserOnly,
            },
            job_fingerprint: String::from("test"),
            total_candidates: 2,
            verified_attempts: 1,
        };
        std::fs::write(&path, serde_json::to_vec(&checkpoint).unwrap())
            .expect("checkpoint should be writable");

        let result = load_checkpoint(
            &path,
            &JobDefinition {
                filename: workspace_path("examples/ALICE_BANK_STATEMENT.pdf"),
                method: arguments::Method::Range(arguments::RangeArgs {
                    add_preceding_zeros: false,
                    lower_bound: 1,
                    upper_bound: 2,
                }),
                verification_mode: VerificationMode::default(),
            },
            "test",
            2,
        );

        let error = result.expect_err("mismatched verification mode should fail");
        assert!(error.to_string().contains("does not match"));
        std::fs::remove_file(path).expect("checkpoint should be removable");
    }

    #[test]
    fn json_output_contains_structured_password_fields() {
        let args = arguments::Arguments {
            number_of_threads: 1,
            batch_size: 8,
            filename: workspace_path("examples/datetime-15012000.pdf"),
            json: true,
            user_password_only: false,
            checkpoint: None,
            resume: None,
            subcommand: arguments::Method::Date(arguments::DateArgs {
                format: "DDMMYYYY".to_string(),
                start: 1999,
                end: 2000,
            }),
        };
        let mut output = Vec::new();

        let code = entrypoint_with_writer(args, CancellationToken::new(), &mut output)
            .expect("json run should succeed");
        assert!(matches!(code, super::Code::Success));

        let payload: serde_json::Value =
            serde_json::from_slice(&output).expect("output should be valid JSON");
        assert_eq!(payload["status"], "success");
        assert_eq!(payload["password"]["kind"], "utf8");
        assert_eq!(payload["password_kind"], "user");
        assert!(payload["password"]["display"]
            .as_str()
            .expect("display should be a string")
            .starts_with('"'));
    }
}
