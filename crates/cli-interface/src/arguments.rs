use std::path::PathBuf;

use clap::{value_parser, Args, Parser, Subcommand};
use engine::crackers::VerificationMode;
use serde::{Deserialize, Serialize};

fn default_worker_threads() -> usize {
    engine::recommended_worker_count()
}

fn default_batch_size() -> usize {
    engine::default_batch_size()
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DictionaryArgs {
    #[clap(required = true)]
    /// Path to the password wordlist.
    pub wordlist: String,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeArgs {
    #[clap(short, long)]
    /// Enabling this adds preceding zeros to number ranges matching the upper bound length.
    pub add_preceding_zeros: bool,

    pub lower_bound: usize,
    pub upper_bound: usize,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomQueryArgs {
    /// Start a brute-force attack with a custom formatted query and a number range like
    /// `ALICE{1000-3000}`.
    pub custom_query: String,

    #[clap(short, long)]
    /// Enabling this adds preceding zeros to number ranges in custom queries.
    ///
    /// For example, `ALICE{10-5000}` starts from `ALICE0010`, matching the width of the ending
    /// range.
    pub add_preceding_zeros: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultQueryArgs {
    #[clap(long, default_value_t = 4, value_parser = value_parser!(u32))]
    /// Minimum brute-force length, inclusive.
    pub min_length: u32,

    #[clap(long, value_parser = value_parser!(u32))]
    /// Maximum brute-force length, inclusive.
    pub max_length: u32,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskArgs {
    /// Hashcat-style bounded mask, for example `?u{4}?d{4}` or `DOC-?d{2,4}`.
    pub mask: String,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainsWordArgs {
    /// Path to the file containing required words, one per line.
    pub wordlist: String,

    #[clap(long, value_parser = value_parser!(usize))]
    /// Minimum candidate length, inclusive.
    pub min_length: usize,

    #[clap(long, value_parser = value_parser!(usize))]
    /// Maximum candidate length, inclusive.
    pub max_length: usize,

    #[clap(long, default_value = "ascii")]
    /// Charset used for the non-word filler positions. One of: ascii, lower, upper, digit, special.
    pub fill_charset: String,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Enumerate a span of years, testing passwords in a configurable date format.
pub struct DateArgs {
    /// Output format built from the tokens `DD`, `MM`, and `YYYY`.
    ///
    /// Examples: `DDMMYYYY`, `DD.MM.YYYY`, `YYYY-MM-DD`.
    #[clap(long, default_value = "DDMMYYYY")]
    pub format: String,

    /// Starting year in format YYYY, inclusive.
    pub start: usize,
    /// Final year in format YYYY, inclusive.
    pub end: usize,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    Wordlist(DictionaryArgs),
    Range(RangeArgs),
    CustomQuery(CustomQueryArgs),
    Mask(MaskArgs),
    ContainsWord(ContainsWordArgs),
    Date(DateArgs),
    DefaultQuery(DefaultQueryArgs),
}

/// Deterministic job identity stored inside checkpoints.
///
/// Runtime-only knobs such as worker count, batch size, output mode, and checkpoint paths are not
/// part of this structure because changing them does not alter the candidate sequence. The PDF path
/// and cracking method are included because changing either would make a checkpoint unsafe to
/// resume. The verification mode is also included because it changes which candidates count as a
/// successful terminal match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobDefinition {
    pub filename: String,
    pub method: Method,
    #[serde(default, skip_serializing_if = "VerificationMode::is_default")]
    pub verification_mode: VerificationMode,
}

// Let's use Clap to ensure our program can only be called with valid parameter combinations.
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
/// A PDF password cracking utility with structured search modes and exact resume-aware progress.
pub struct Arguments {
    #[clap(
        short = 'n',
        long = "threads",
        visible_alias = "number-of-threads",
        default_value_t = default_worker_threads(),
        value_parser = value_parser!(usize)
    )]
    /// Number of worker threads.
    pub number_of_threads: usize,

    #[clap(
        long,
        default_value_t = default_batch_size(),
        value_parser = value_parser!(usize)
    )]
    /// Number of password candidates sent to a worker in each batch.
    pub batch_size: usize,

    #[clap(short = 'f', long = "file", visible_alias = "filename")]
    /// The filename of the PDF.
    pub filename: String,

    #[clap(long)]
    /// Emit a single JSON object to stdout instead of human-readable output.
    pub json: bool,

    #[clap(long)]
    /// Only test the PDF user/open password path and skip owner-password acceptance checks.
    ///
    /// This is an explicit opt-in fast mode. By default pdfrip still accepts both user and owner
    /// passwords exactly as before.
    pub user_password_only: bool,

    #[clap(long)]
    /// Save a resumable checkpoint to this path when the run is cancelled.
    pub checkpoint: Option<PathBuf>,

    #[clap(long)]
    /// Resume from a previously saved checkpoint after validating that the job definition matches
    /// the current CLI arguments.
    pub resume: Option<PathBuf>,

    #[command(subcommand)]
    /// Brute-forcing method.
    pub subcommand: Method,
}

impl Arguments {
    /// Returns the password verification mode selected by the current CLI flags.
    pub fn verification_mode(&self) -> VerificationMode {
        if self.user_password_only {
            VerificationMode::UserOnly
        } else {
            VerificationMode::default()
        }
    }

    /// Returns the stable job identity used for checkpoint validation.
    pub fn job_definition(&self) -> JobDefinition {
        JobDefinition {
            filename: self.filename.clone(),
            method: self.subcommand.clone(),
            verification_mode: self.verification_mode(),
        }
    }

    /// Returns the checkpoint output path for the current run, if any.
    ///
    /// When resuming from a checkpoint without explicitly providing `--checkpoint`, the engine
    /// writes any new cancellation checkpoint back to the resume path.
    pub fn checkpoint_output_path(&self) -> Option<PathBuf> {
        self.checkpoint.clone().or_else(|| self.resume.clone())
    }
}

pub fn args() -> Arguments {
    Arguments::parse()
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use engine::crackers::VerificationMode;

    use super::{Arguments, JobDefinition, Method, RangeArgs};

    #[test]
    fn parser_maps_user_password_only_flag_to_the_fast_mode() {
        let args = Arguments::try_parse_from([
            "pdfrip",
            "--file",
            "encrypted.pdf",
            "--user-password-only",
            "range",
            "1",
            "9",
        ])
        .expect("CLI parsing should succeed");

        assert!(args.user_password_only);
        assert_eq!(args.verification_mode(), VerificationMode::UserOnly);
    }

    #[test]
    fn help_text_explains_that_user_only_mode_skips_owner_password_checks() {
        let mut help = Vec::new();
        Arguments::command()
            .write_long_help(&mut help)
            .expect("help rendering should succeed");
        let help = String::from_utf8(help).expect("help output should stay valid utf-8");

        assert!(help.contains("--user-password-only"));
        assert!(help.contains("Only test the PDF user/open password path"));
        assert!(help.contains("skip owner-password acceptance checks"));
        assert!(help.contains("explicit opt-in fast mode"));
        assert!(help.contains("accepts both user and owner"));
    }

    #[test]
    fn default_job_definition_serialization_stays_backward_compatible() {
        let job = JobDefinition {
            filename: String::from("encrypted.pdf"),
            method: Method::Range(RangeArgs {
                add_preceding_zeros: false,
                lower_bound: 1,
                upper_bound: 9,
            }),
            verification_mode: VerificationMode::default(),
        };

        let json = serde_json::to_string(&job).expect("job definition should serialize");
        assert!(!json.contains("verification_mode"));
    }

    #[test]
    fn user_only_mode_is_serialized_into_checkpoint_job_definitions() {
        let job = JobDefinition {
            filename: String::from("encrypted.pdf"),
            method: Method::Range(RangeArgs {
                add_preceding_zeros: false,
                lower_bound: 1,
                upper_bound: 9,
            }),
            verification_mode: VerificationMode::UserOnly,
        };

        let json = serde_json::to_string(&job).expect("job definition should serialize");
        assert!(json.contains("\"verification_mode\":\"user_only\""));
    }
}
