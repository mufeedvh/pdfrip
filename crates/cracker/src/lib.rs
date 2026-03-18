//! High-level PDF password cracking primitives.
//!
//! # Overview
//!
//! This crate exposes a small API used by the engine:
//!
//! - [`PDFCracker`] performs one-time file loading and verifier preparation
//! - [`PDFCrackerState`] provides a cheap worker-local handle for repeated
//!   password attempts
//!
//! The critical architectural change in this version is that password attempts
//! no longer rebuild `pdf::file::Storage` or reload trailer/xref data on every
//! candidate. Instead, the crate extracts the security envelope once and then
//! performs direct password verification calls against the prepared metadata.
//!
//! # Security model
//!
//! Only Standard password-based PDF encryption revisions supported by the
//! `pdf` crate verifier path are accepted. Unsupported or malformed encryption
//! setups fail closed during preparation instead of being misreported as normal
//! wrong-password attempts.
//!
//! # Logging
//!
//! Logging is intentionally structured and password-free. We log verifier
//! preparation metadata and unexpected runtime failures, but we never log
//! password candidates.

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

mod verifier;

use verifier::{PasswordAttemptScratch, PreparedPasswordVerifier};

/// Classification for a password accepted by the Standard Security Handler.
///
/// A candidate can unlock a PDF either as the user password or as the owner
/// password. Distinguishing these cases is useful for user-facing output because
/// blank user passwords and owner-password-only matches were a repeated source
/// of confusion in the historical issue backlog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordKind {
    User,
    Owner,
}

/// Controls which Standard Security Handler password paths are accepted.
///
/// # Purpose
///
/// PDF documents can accept two credential classes:
///
/// - the **user/open** password, which is the document-opening credential
/// - the **owner/permissions** password, which may also unlock the file
///
/// The default mode preserves historical pdfrip behavior by accepting both.
/// [`VerificationMode::UserOnly`] is an explicit opt-in fast path that skips the
/// owner-password acceptance logic entirely.
///
/// # Checkpoint and reporting implications
///
/// The selected mode is part of the logical cracking job definition. Resuming a
/// checkpoint with a different mode would be unsafe because it changes which
/// candidates can terminate the search successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    /// Preserve the traditional behavior: accept both user and owner passwords.
    #[default]
    UserAndOwner,
    /// Only accept the user/open password and skip owner-password checks.
    UserOnly,
}

impl VerificationMode {
    /// Returns `true` when owner-password acceptance should remain enabled.
    pub const fn accepts_owner_passwords(self) -> bool {
        matches!(self, Self::UserAndOwner)
    }

    /// Returns `true` when the mode is the backwards-compatible default.
    ///
    /// This helper is used when serializing checkpoint job definitions so the
    /// default mode keeps the legacy on-disk representation.
    pub const fn is_default(&self) -> bool {
        matches!(*self, Self::UserAndOwner)
    }

    /// Returns a stable log-friendly label for the configured mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserAndOwner => "user_and_owner",
            Self::UserOnly => "user_only",
        }
    }
}

/// Prepared cracking input for a single PDF document.
///
/// # Purpose
///
/// This type owns the immutable verifier state shared by all cracking workers.
/// Construction performs the expensive one-time work:
///
/// - reading the file from disk
/// - extracting the security envelope
/// - validating that the file uses a supported password-based PDF handler
///
/// # Examples
///
/// ```no_run
/// # fn demo() -> anyhow::Result<()> {
/// let cracker = cracker::PDFCracker::from_file("examples/passwords_aes_256.pdf")?;
/// let mut state = cracker::PDFCrackerState::from_cracker(&cracker)?;
/// assert!(!state.attempt(b"definitely-wrong"));
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Construction fails for unreadable files, malformed PDFs, unencrypted files,
/// unsupported security handlers, or broken encryption metadata.
#[derive(Clone)]
pub struct PDFCracker {
    verifier: Arc<PreparedPasswordVerifier>,
    verification_mode: VerificationMode,
}

impl PDFCracker {
    /// Reads a PDF from disk and prepares a direct password verifier.
    ///
    /// This is the backwards-compatible constructor. It preserves the original
    /// behavior by accepting both user and owner passwords.
    pub fn from_file(path: &str) -> Result<Self> {
        Self::from_file_with_mode(path, VerificationMode::default())
    }

    /// Reads a PDF from disk and prepares a direct password verifier configured
    /// for the requested verification mode.
    ///
    /// # Parameters
    ///
    /// - `path`: filesystem path to the target PDF.
    /// - `verification_mode`: whether cracking should accept both user and owner
    ///   passwords or only the user/open password.
    ///
    /// # Returns
    ///
    /// Returns a prepared cracker that can cheaply spawn many
    /// [`PDFCrackerState`] worker handles.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if verifier preparation
    /// fails for any reason.
    ///
    /// # Design rationale
    ///
    /// The mode lives on the prepared cracker instead of the engine so worker
    /// coordination remains PDF-semantic-free. The engine simply executes a
    /// configured verifier.
    pub fn from_file_with_mode(path: &str, verification_mode: VerificationMode) -> Result<Self> {
        info!(
            "cracker.prepare.start path={} verification_mode={}",
            path,
            verification_mode.as_str()
        );

        let pdf_file: Arc<[u8]> = fs::read(path)
            .with_context(|| format!("Failed to read PDF file '{}'", path))?
            .into();
        let verifier = PreparedPasswordVerifier::prepare(pdf_file)
            .with_context(|| format!("Failed to prepare password verifier for '{}'", path))?;

        info!(
            "cracker.prepare.ready path={} revision={} variant={} encrypt_metadata={} verification_mode={}",
            path,
            verifier.revision(),
            verifier.variant(),
            verifier.encrypt_metadata(),
            verification_mode.as_str()
        );

        Ok(Self {
            verifier: Arc::new(verifier),
            verification_mode,
        })
    }

    /// Classifies a password accepted under the current verification mode.
    ///
    /// Returns `Ok(None)` when the password is invalid for this document or
    /// when it would only be accepted by a disabled verification path such as an
    /// owner-password-only match in [`VerificationMode::UserOnly`].
    pub fn classify_password(&self, password: &[u8]) -> Result<Option<PasswordKind>> {
        self.verifier
            .classify_password(password, self.verification_mode)
    }

    /// Returns the configured password verification mode.
    pub fn verification_mode(&self) -> VerificationMode {
        self.verification_mode
    }

    /// Returns the prepared verifier's normalized revision number.
    pub fn revision(&self) -> u32 {
        self.verifier.revision()
    }

    /// Returns the prepared verifier's short variant label.
    pub fn variant(&self) -> &'static str {
        self.verifier.variant()
    }

    /// Indicates whether metadata is encrypted for this document.
    ///
    /// This mirrors `/EncryptMetadata` after normalization. It is primarily useful for regression
    /// tests and diagnostics because revision 4 derivation changes when metadata encryption is
    /// disabled.
    pub fn encrypt_metadata(&self) -> bool {
        self.verifier.encrypt_metadata()
    }
}

/// Worker-local password verifier handle.
///
/// # Purpose
///
/// The engine creates one state per worker thread. Creating a state is cheap:
/// it only clones an [`Arc`] to the prepared verifier and initializes a small
/// amount of worker-local bookkeeping, including reusable scratch buffers for
/// password normalization/verification.
///
/// # Error handling
///
/// The constructor currently returns `Result` for API compatibility and future
/// extensibility, even though the current implementation cannot fail once the
/// parent [`PDFCracker`] has been prepared successfully.
pub struct PDFCrackerState {
    verifier: Arc<PreparedPasswordVerifier>,
    verification_mode: VerificationMode,
    scratch: PasswordAttemptScratch,
    logged_runtime_error: bool,
}

impl PDFCrackerState {
    /// Creates a worker-local verifier state from a prepared cracker.
    pub fn from_cracker(pdf_file: &PDFCracker) -> Result<Self> {
        debug!(
            "cracker.worker_state.ready revision={} variant={} verification_mode={}",
            pdf_file.verifier.revision(),
            pdf_file.verifier.variant(),
            pdf_file.verification_mode.as_str()
        );

        Ok(Self {
            verifier: Arc::clone(&pdf_file.verifier),
            verification_mode: pdf_file.verification_mode,
            scratch: PasswordAttemptScratch::default(),
            logged_runtime_error: false,
        })
    }

    /// Verifies a single password candidate.
    ///
    /// # Parameters
    ///
    /// - `password`: raw password bytes to test.
    ///
    /// # Returns
    ///
    /// Returns `true` when the candidate is accepted as a valid PDF password
    /// under the configured [`VerificationMode`] and `false` for a normal
    /// wrong-password result.
    ///
    /// # Error handling
    ///
    /// Unexpected verifier failures are logged once per worker and surfaced to
    /// the engine as `false`. Preparation is designed to catch unsupported
    /// cases up front, so runtime failures should be rare and actionable.
    pub fn attempt(&mut self, password: &[u8]) -> bool {
        match self.verifier.verify_password_with_scratch(
            password,
            self.verification_mode,
            &mut self.scratch,
        ) {
            Ok(result) => {
                if result {
                    debug!(
                        "cracker.password.accepted revision={} variant={} verification_mode={}",
                        self.verifier.revision(),
                        self.verifier.variant(),
                        self.verification_mode.as_str()
                    );
                }
                result
            }
            Err(error) => {
                if !self.logged_runtime_error {
                    error!(
                        "cracker.password.verify_error revision={} variant={} verification_mode={} error={:#}",
                        self.verifier.revision(),
                        self.verifier.variant(),
                        self.verification_mode.as_str(),
                        error
                    );
                    self.logged_runtime_error = true;
                }
                false
            }
        }
    }
}
