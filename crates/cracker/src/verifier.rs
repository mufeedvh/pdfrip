//! Prepared PDF password verification for the `cracker` crate.
//!
//! # Architecture
//!
//! The old cracker hot path rebuilt `pdf::file::Storage` state for every
//! password candidate. That approach was correct but expensive because each
//! attempt re-read the trailer, cross-reference data, and encryption metadata
//! before it could even begin cryptographic verification.
//!
//! This module moves that work into a one-time preparation step:
//!
//! 1. locate the PDF header and `startxref`
//! 2. read the xref/trailer chain once
//! 3. resolve only the security-relevant `/Encrypt` dictionary and `/ID`
//! 4. normalize the supported Standard Security Handler profile
//! 5. verify passwords with a prepared direct classifier that never re-enters
//!    general PDF storage loading during the hot path
//!
//! The result is a practical dedicated verifier layer that keeps general PDF
//! document loading out of the password-attempt loop while still using the
//! `pdf` crate during preparation as a fail-closed metadata/parser oracle.
//!
//! # Scope and limitations
//!
//! This resolver is intentionally minimal. It is designed only for extracting
//! the security envelope required for password verification. It is **not** a
//! general replacement for `pdf::file::Storage`, and it intentionally fails
//! closed when it encounters unsupported security handlers or malformed inputs.
//!
//! # Security considerations
//!
//! - Only the Standard password-based security handler is accepted.
//! - Unsupported `/Filter` or `/SubFilter` values are rejected during
//!   preparation rather than silently treated as bad passwords.
//! - Candidate passwords are never logged.
//! - Raw PDF bytes are only retained during preparation; the hot path stores
//!   only the parsed encryption metadata needed for verification.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::generic_array::sequence::Split;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, bail, Context, Result};
use log::debug;
use pdf::backend::Backend;
use pdf::crypt::{CryptDict, Decoder, Rc4};
use pdf::enc::{decode, StreamFilter};
use pdf::object::{Object, ObjectStream, ParseOptions, PlainRef, RcRef, Ref, Resolve};
use pdf::parser::{parse, parse_indirect_object, Lexer, ParseFlags};
use pdf::primitive::{Dictionary, Primitive};
use pdf::xref::{XRef, XRefTable};
use pdf::PdfError;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::{PasswordKind, VerificationMode};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

const MAX_R56_PASSWORD_LEN: usize = 127;
const MAX_REVISION_6_BLOCK_LEN: usize = 64;
const MAX_REVISION_6_USER_FIELD_LEN: usize = 48;
const REVISION_6_REPEAT_COUNT: usize = 64;
const MAX_REVISION_6_REPEATED_LEN: usize =
    MAX_R56_PASSWORD_LEN + MAX_REVISION_6_BLOCK_LEN + MAX_REVISION_6_USER_FIELD_LEN;
const MAX_REVISION_6_DATA_LEN: usize = MAX_REVISION_6_REPEATED_LEN * REVISION_6_REPEAT_COUNT;

const PASSWORD_PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

/// A prepared verifier that contains only the immutable metadata required to
/// test password candidates against a PDF Standard Security Handler.
///
/// # Design
///
/// The verifier stores:
///
/// - the document identifier (`/ID[0]`)
/// - a normalized security profile extracted from `/Encrypt`
/// - password-classification material derived from the Standard Security Handler fields
///
/// It deliberately does **not** retain the full source PDF after preparation.
/// Once the security envelope has been extracted, password verification is a
/// direct cryptographic check with no further trailer/xref/object traversal.
#[derive(Clone)]
pub(crate) struct PreparedPasswordVerifier {
    document_id: Vec<u8>,
    profile: SecurityProfile,
    classifier: PasswordClassifier,
}

/// Worker-local reusable buffers for password verification.
///
/// The prepared verifier is immutable and shared between workers. Any scratch space that benefits
/// from reuse therefore lives in the worker-local state so repeated password attempts can avoid
/// rebuilding the same heap-backed temporary buffers on every call.
///
/// # Design rationale
///
/// The most allocation-sensitive paths are the revision 5/6 password normalizer and the revision 6
/// hardened KDF. Both need temporary byte storage, but neither requires a fresh allocation per
/// attempt. Keeping those buffers here lets a worker pay the allocation cost once and then reuse
/// the same backing memory across millions of password candidates.
pub(crate) struct PasswordAttemptScratch {
    normalized_r56_password: Vec<u8>,
    revision_6_work_buffer: Vec<u8>,
}

impl Default for PasswordAttemptScratch {
    fn default() -> Self {
        Self {
            normalized_r56_password: Vec::with_capacity(MAX_R56_PASSWORD_LEN),
            revision_6_work_buffer: Vec::new(),
        }
    }
}

impl PreparedPasswordVerifier {
    /// Builds a verifier from raw PDF bytes.
    ///
    /// # Parameters
    ///
    /// - `pdf_bytes`: immutable bytes for the target PDF file.
    ///
    /// # Returns
    ///
    /// Returns a prepared verifier when the file contains a supported Standard
    /// Security Handler. Returns an error for unencrypted files, malformed
    /// trailer/encryption data, or unsupported security handlers.
    ///
    /// # Errors
    ///
    /// This method fails when:
    ///
    /// - the PDF header or xref/trailer chain cannot be parsed
    /// - `/ID` or `/Encrypt` is missing or malformed
    /// - the file uses a non-standard or unsupported security handler
    /// - the `pdf` crate rejects the parsed cryptography metadata during a
    ///   no-password self-check
    ///
    /// # Security
    ///
    /// Unsupported cases fail closed here so that the hot path never confuses a
    /// structural error with a normal wrong-password result.
    pub(crate) fn prepare(pdf_bytes: Arc<[u8]>) -> Result<Self> {
        let start_offset = pdf_bytes
            .locate_start_offset()
            .context("Failed to locate the PDF header")?;

        debug!(
            "cracker.verifier.prepare.start bytes={} start_offset={}",
            pdf_bytes.len(),
            start_offset
        );

        let resolver = SecurityEnvelopeResolver::new(Arc::clone(&pdf_bytes), start_offset);
        let (refs, trailer) = pdf_bytes
            .read_xref_table_and_trailer(start_offset, &resolver)
            .context("Failed to read the PDF xref/trailer chain")?;
        resolver.install_refs(refs);

        let encrypt_entry = trailer.get("Encrypt").cloned().ok_or_else(|| {
            anyhow!("PDF is not encrypted with the Standard password-based security handler")
        })?;
        let document_id = extract_document_id(&trailer)?;
        let resolved_encrypt = resolver
            .resolve_encrypt_optional_reference(encrypt_entry)
            .map_err(anyhow::Error::from)
            .context("Failed to resolve trailer /Encrypt entry")?;
        let encrypt_dict = resolved_encrypt
            .clone()
            .into_dictionary()
            .map_err(anyhow::Error::from)
            .context("Trailer /Encrypt entry was not a dictionary")?;

        let profile = SecurityProfile::from_encrypt_dictionary(&resolver, &encrypt_dict)
            .context("Unsupported or malformed PDF security handler")?;
        let classifier = PasswordClassifier::from_encrypt_dictionary(&profile, &encrypt_dict)
            .context("Failed to prepare password-kind classifier from the encryption dictionary")?;
        let crypt_dict = CryptDict::from_primitive(Primitive::Dictionary(encrypt_dict), &resolver)
            .map_err(anyhow::Error::from)
            .context("Failed to parse the Standard Security Handler dictionary")?;

        match Decoder::from_password(&crypt_dict, &document_id, b"") {
            Ok(_) => debug!(
                "cracker.verifier.prepare.blank_password_ok revision={} version={} variant={} encrypt_metadata={}",
                profile.revision,
                profile.version,
                profile.variant.as_str(),
                profile.encrypt_metadata
            ),
            Err(PdfError::InvalidPassword) => debug!(
                "cracker.verifier.prepare.blank_password_rejected revision={} version={} variant={} encrypt_metadata={}",
                profile.revision,
                profile.version,
                profile.variant.as_str(),
                profile.encrypt_metadata
            ),
            Err(error) => {
                return Err(anyhow!(error).context(
                    "Prepared verifier self-check failed before password cracking started",
                ));
            }
        }

        debug!(
            "cracker.verifier.prepare.ready revision={} version={} variant={} encrypt_metadata={}",
            profile.revision,
            profile.version,
            profile.variant.as_str(),
            profile.encrypt_metadata
        );

        Ok(Self {
            document_id,
            profile,
            classifier,
        })
    }

    /// Verifies a single password candidate.
    ///
    /// # Parameters
    ///
    /// - `password`: raw password bytes exactly as produced by the cracking
    ///   engine.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` when the candidate is accepted under the active
    /// [`VerificationMode`], `Ok(false)` for a normal wrong-password result,
    /// and `Err(...)` only when the verifier encounters an unexpected runtime
    /// problem.
    ///
    /// # Errors
    ///
    /// Errors are reserved for malformed or unsupported runtime conditions. A
    /// wrong password is **not** treated as an error.
    /// Verifies a single password candidate using reusable worker-local scratch buffers.
    pub(crate) fn verify_password_with_scratch(
        &self,
        password: &[u8],
        verification_mode: VerificationMode,
        scratch: &mut PasswordAttemptScratch,
    ) -> Result<bool> {
        Ok(self
            .classifier
            .classify_with_scratch(&self.document_id, password, verification_mode, scratch)?
            .is_some())
    }

    /// Classifies a valid password as either a user or owner password when the revision allows
    /// that distinction to be determined from the Standard Security Handler metadata.
    ///
    /// Returns `Ok(None)` for invalid passwords or for passwords that would only be accepted by a
    /// disabled verification path, such as an owner-password-only match while running in
    /// [`VerificationMode::UserOnly`]. Unexpected classifier failures are surfaced as errors
    /// instead of being confused with a wrong-password result.
    pub(crate) fn classify_password(
        &self,
        password: &[u8],
        verification_mode: VerificationMode,
    ) -> Result<Option<PasswordKind>> {
        self.classifier
            .classify(&self.document_id, password, verification_mode)
            .context("Failed to classify an accepted PDF password")
    }

    /// Returns the normalized security revision extracted during preparation.
    pub(crate) fn revision(&self) -> u32 {
        self.profile.revision
    }

    /// Returns a short human-readable description of the active verifier mode.
    pub(crate) fn variant(&self) -> &'static str {
        self.profile.variant.as_str()
    }

    /// Indicates whether `/EncryptMetadata` was enabled in the source file.
    pub(crate) fn encrypt_metadata(&self) -> bool {
        self.profile.encrypt_metadata
    }
}

/// Normalized security metadata extracted from `/Encrypt`.
///
/// This type exists for two reasons:
///
/// 1. to validate that we only accept supported Standard Security Handler
///    variants before cracking starts
/// 2. to provide structured, password-free logging that explains what kind of
///    document the verifier prepared
#[derive(Clone, Debug)]
struct SecurityProfile {
    version: u32,
    revision: u32,
    variant: SecurityVariant,
    encrypt_metadata: bool,
}

impl SecurityProfile {
    /// Parses and validates the subset of `/Encrypt` we care about.
    fn from_encrypt_dictionary(
        resolver: &SecurityEnvelopeResolver,
        encrypt_dict: &Dictionary,
    ) -> Result<Self> {
        let filter = required_name(encrypt_dict, "Encrypt", "Filter")?;
        if filter != "Standard" {
            bail!("Unsupported security handler filter=/{}", filter);
        }

        if let Some(sub_filter) = encrypt_dict.get("SubFilter") {
            let sub_filter = sub_filter
                .as_name()
                .map_err(anyhow::Error::from)
                .context("/Encrypt /SubFilter was not a name")?;
            bail!("Unsupported security handler sub-filter=/{}", sub_filter);
        }

        let version = required_u32(encrypt_dict, "Encrypt", "V")?;
        let revision = required_u32(encrypt_dict, "Encrypt", "R")?;
        let encrypt_metadata = optional_bool(encrypt_dict, "EncryptMetadata")?.unwrap_or(true);

        let variant = match revision {
            2 => {
                if version != 1 {
                    bail!(
                        "Unsupported Standard security handler combination V={} R={}",
                        version,
                        revision
                    );
                }
                SecurityVariant::Rc4Revision2
            }
            3 => {
                if version != 2 {
                    bail!(
                        "Unsupported Standard security handler combination V={} R={}",
                        version,
                        revision
                    );
                }
                SecurityVariant::Rc4Revision3
            }
            4 => {
                if version != 4 {
                    bail!(
                        "Unsupported Standard security handler combination V={} R={}",
                        version,
                        revision
                    );
                }

                match default_crypt_filter_method(resolver, encrypt_dict)?.as_str() {
                    "V2" => SecurityVariant::Rc4Revision4,
                    "AESV2" => SecurityVariant::Aes128Revision4,
                    method => {
                        bail!("Unsupported revision 4 crypt filter method /{}", method)
                    }
                }
            }
            5 => {
                if version != 5 {
                    bail!(
                        "Unsupported Standard security handler combination V={} R={}",
                        version,
                        revision
                    );
                }

                let method = default_crypt_filter_method(resolver, encrypt_dict)?;
                if method != "AESV3" {
                    bail!("Unsupported revision 5 crypt filter method /{}", method);
                }
                SecurityVariant::Aes256Revision5
            }
            6 => {
                if version != 5 {
                    bail!(
                        "Unsupported Standard security handler combination V={} R={}",
                        version,
                        revision
                    );
                }

                let method = default_crypt_filter_method(resolver, encrypt_dict)?;
                if method != "AESV3" {
                    bail!("Unsupported revision 6 crypt filter method /{}", method);
                }
                SecurityVariant::Aes256Revision6
            }
            other => bail!("Unsupported Standard Security Handler revision R={}", other),
        };

        Ok(Self {
            version,
            revision,
            variant,
            encrypt_metadata,
        })
    }
}

/// The supported Standard Security Handler variants for the current verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecurityVariant {
    Rc4Revision2,
    Rc4Revision3,
    Rc4Revision4,
    Aes128Revision4,
    Aes256Revision5,
    Aes256Revision6,
}

impl SecurityVariant {
    /// Returns a stable log-friendly description of the supported variant.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Rc4Revision2 => "rc4-r2",
            Self::Rc4Revision3 => "rc4-r3",
            Self::Rc4Revision4 => "rc4-r4",
            Self::Aes128Revision4 => "aes128-r4",
            Self::Aes256Revision5 => "aes256-r5",
            Self::Aes256Revision6 => "aes256-r6",
        }
    }
}

#[derive(Clone)]
struct Rc4PasswordClassifier {
    revision: u32,
    key_size: usize,
    owner: Vec<u8>,
    user: Vec<u8>,
    permissions: i32,
    encrypt_metadata: bool,
}

#[derive(Clone)]
enum PasswordClassifier {
    Rc4(Rc4PasswordClassifier),
    AesRevision5 { owner: Vec<u8>, user: Vec<u8> },
    AesRevision6 { owner: Vec<u8>, user: Vec<u8> },
}

impl PasswordClassifier {
    fn from_encrypt_dictionary(
        profile: &SecurityProfile,
        encrypt_dict: &Dictionary,
    ) -> Result<Self> {
        match profile.variant {
            SecurityVariant::Rc4Revision2
            | SecurityVariant::Rc4Revision3
            | SecurityVariant::Rc4Revision4
            | SecurityVariant::Aes128Revision4 => {
                let key_bits = encrypt_dict
                    .get("Length")
                    .map(|value| {
                        value
                            .as_u32()
                            .map_err(anyhow::Error::from)
                            .context("Encrypt /Length was not an integer")
                    })
                    .transpose()?
                    .unwrap_or(40);
                let key_size = (key_bits as usize) / 8;
                if key_size == 0 || key_size > 16 {
                    bail!("unsupported RC4/AES-128 key size {key_bits} bits");
                }

                let owner = required_bytes(encrypt_dict, "Encrypt", "O")?;
                let user = required_bytes(encrypt_dict, "Encrypt", "U")?;
                ensure_rc4_field_lengths(&owner, &user)?;

                Ok(Self::Rc4(Rc4PasswordClassifier {
                    revision: profile.revision,
                    key_size,
                    owner,
                    user,
                    permissions: required_i32(encrypt_dict, "Encrypt", "P")?,
                    encrypt_metadata: profile.encrypt_metadata,
                }))
            }
            SecurityVariant::Aes256Revision5 => Ok(Self::AesRevision5 {
                owner: required_bytes(encrypt_dict, "Encrypt", "O")?,
                user: required_bytes(encrypt_dict, "Encrypt", "U")?,
            }),
            SecurityVariant::Aes256Revision6 => Ok(Self::AesRevision6 {
                owner: required_bytes(encrypt_dict, "Encrypt", "O")?,
                user: required_bytes(encrypt_dict, "Encrypt", "U")?,
            }),
        }
    }

    fn classify(
        &self,
        document_id: &[u8],
        password: &[u8],
        verification_mode: VerificationMode,
    ) -> Result<Option<PasswordKind>> {
        let mut scratch = PasswordAttemptScratch::default();
        self.classify_with_scratch(document_id, password, verification_mode, &mut scratch)
    }

    fn classify_with_scratch(
        &self,
        document_id: &[u8],
        password: &[u8],
        verification_mode: VerificationMode,
        scratch: &mut PasswordAttemptScratch,
    ) -> Result<Option<PasswordKind>> {
        match self {
            Self::Rc4(classifier) => Ok(classify_rc4_password(
                classifier,
                document_id,
                password,
                verification_mode,
            )?),
            Self::AesRevision5 { owner, user } => {
                classify_r5_password(owner, user, password, verification_mode, scratch)
            }
            Self::AesRevision6 { owner, user } => {
                classify_r6_password(owner, user, password, verification_mode, scratch)
            }
        }
    }
}

fn classify_rc4_password(
    classifier: &Rc4PasswordClassifier,
    document_id: &[u8],
    password: &[u8],
    verification_mode: VerificationMode,
) -> Result<Option<PasswordKind>> {
    let user_key = derive_user_password_rc4(
        classifier.revision,
        classifier.key_size,
        &classifier.owner,
        classifier.permissions,
        document_id,
        classifier.encrypt_metadata,
        password,
    );
    if check_password_rc4(
        classifier.revision,
        &classifier.user,
        document_id,
        &user_key[..classifier.key_size.min(16)],
    ) {
        return Ok(Some(PasswordKind::User));
    }

    if !verification_mode.accepts_owner_passwords() {
        return Ok(None);
    }

    let password_wrap_key =
        derive_owner_password_rc4(classifier.revision, classifier.key_size, password)?;
    let mut data = [0u8; 32];
    data.copy_from_slice(&classifier.owner);
    let mut round_key = [0u8; 16];
    let rounds = if classifier.revision == 2 { 1u8 } else { 20u8 };
    for round in 0..rounds {
        round_key[..classifier.key_size].copy_from_slice(&password_wrap_key[..classifier.key_size]);
        for byte in &mut round_key[..classifier.key_size] {
            *byte ^= round;
        }
        Rc4::encrypt(&round_key[..classifier.key_size], &mut data);
    }

    let owner_key = derive_user_password_rc4(
        classifier.revision,
        classifier.key_size,
        &classifier.owner,
        classifier.permissions,
        document_id,
        classifier.encrypt_metadata,
        &data,
    );

    if check_password_rc4(
        classifier.revision,
        &classifier.user,
        document_id,
        &owner_key[..classifier.key_size.min(16)],
    ) {
        Ok(Some(PasswordKind::Owner))
    } else {
        Ok(None)
    }
}

fn derive_user_password_rc4(
    revision: u32,
    key_size: usize,
    owner: &[u8],
    permissions: i32,
    document_id: &[u8],
    encrypt_metadata: bool,
    password: &[u8],
) -> [u8; 16] {
    let mut hash = md5::Context::new();
    if password.len() < 32 {
        hash.consume(password);
        hash.consume(&PASSWORD_PADDING[..32 - password.len()]);
    } else {
        hash.consume(&password[..32]);
    }

    hash.consume(owner);
    hash.consume(permissions.to_le_bytes());
    hash.consume(document_id);

    if revision >= 4 && !encrypt_metadata {
        hash.consume([0xff, 0xff, 0xff, 0xff]);
    }

    let mut data = *hash.compute();
    if revision >= 3 {
        for _ in 0..50 {
            data = *md5::compute(&data[..key_size.min(16)]);
        }
    }

    data
}

fn derive_owner_password_rc4(revision: u32, key_size: usize, password: &[u8]) -> Result<[u8; 16]> {
    if key_size > 16 {
        bail!("key size > 16");
    }

    let mut hash = md5::Context::new();
    if password.len() < 32 {
        hash.consume(password);
        hash.consume(&PASSWORD_PADDING[..32 - password.len()]);
    } else {
        hash.consume(&password[..32]);
    }

    let mut data = *hash.compute();
    if revision >= 3 {
        for _ in 0..50 {
            data = *md5::compute(&data[..key_size]);
        }
    }

    Ok(data)
}

fn check_password_rc4(revision: u32, document_user: &[u8], document_id: &[u8], key: &[u8]) -> bool {
    if revision == 2 {
        compute_u_rev_2(key).as_slice() == document_user
    } else {
        document_user.starts_with(&compute_u_rev_3_4(document_id, key))
    }
}

fn compute_u_rev_2(key: &[u8]) -> [u8; 32] {
    let mut data = PASSWORD_PADDING;
    Rc4::encrypt(key, &mut data);
    data
}

fn compute_u_rev_3_4(document_id: &[u8], key: &[u8]) -> [u8; 16] {
    let mut hash = md5::Context::new();
    hash.consume(PASSWORD_PADDING);
    hash.consume(document_id);

    let mut data = *hash.compute();
    Rc4::encrypt(key, &mut data);

    let mut round_key = [0u8; 16];
    for round in 1u8..=19 {
        round_key[..key.len()].copy_from_slice(key);
        for byte in &mut round_key[..key.len()] {
            *byte ^= round;
        }
        Rc4::encrypt(&round_key[..key.len()], &mut data);
    }

    data
}

fn classify_r5_password(
    owner: &[u8],
    user: &[u8],
    password: &[u8],
    verification_mode: VerificationMode,
    scratch: &mut PasswordAttemptScratch,
) -> Result<Option<PasswordKind>> {
    let password_encoded =
        normalize_r56_password_into(password, &mut scratch.normalized_r56_password)?;
    ensure_r56_field_lengths(owner, user)?;

    let user_hash = &user[0..32];
    let user_validation_salt = &user[32..40];
    let owner_hash = &owner[0..32];
    let owner_validation_salt = &owner[32..40];

    let mut user_check_hash = Sha256::new();
    user_check_hash.update(password_encoded);
    user_check_hash.update(user_validation_salt);
    if user_check_hash.finalize().as_slice() == user_hash {
        return Ok(Some(PasswordKind::User));
    }

    if !verification_mode.accepts_owner_passwords() {
        return Ok(None);
    }

    let mut owner_check_hash = Sha256::new();
    owner_check_hash.update(password_encoded);
    owner_check_hash.update(owner_validation_salt);
    owner_check_hash.update(user);
    if owner_check_hash.finalize().as_slice() == owner_hash {
        return Ok(Some(PasswordKind::Owner));
    }

    Ok(None)
}

fn classify_r6_password(
    owner: &[u8],
    user: &[u8],
    password: &[u8],
    verification_mode: VerificationMode,
    scratch: &mut PasswordAttemptScratch,
) -> Result<Option<PasswordKind>> {
    let password_encoded =
        normalize_r56_password_into(password, &mut scratch.normalized_r56_password)?;
    ensure_r56_field_lengths(owner, user)?;

    let user_hash = &user[0..32];
    let user_validation_salt = &user[32..40];
    let owner_hash = &owner[0..32];
    let owner_validation_salt = &owner[32..40];

    if revision_6_kdf_with_scratch(
        password_encoded,
        user_validation_salt,
        b"",
        &mut scratch.revision_6_work_buffer,
    ) == user_hash
    {
        return Ok(Some(PasswordKind::User));
    }

    if !verification_mode.accepts_owner_passwords() {
        return Ok(None);
    }

    if revision_6_kdf_with_scratch(
        password_encoded,
        owner_validation_salt,
        user,
        &mut scratch.revision_6_work_buffer,
    ) == owner_hash
    {
        return Ok(Some(PasswordKind::Owner));
    }

    Ok(None)
}

fn normalize_r56_password_into<'a>(password: &[u8], output: &'a mut Vec<u8>) -> Result<&'a [u8]> {
    output.clear();

    if password_is_saslprep_identity_ascii(password) {
        output.extend_from_slice(&password[..password.len().min(MAX_R56_PASSWORD_LEN)]);
        return Ok(output.as_slice());
    }

    let unicode = std::str::from_utf8(password).map_err(|_| anyhow!(PdfError::InvalidPassword))?;
    let prepped = stringprep::saslprep(unicode).map_err(|_| anyhow!(PdfError::InvalidPassword))?;
    let bytes = prepped.as_bytes();
    output.extend_from_slice(&bytes[..bytes.len().min(MAX_R56_PASSWORD_LEN)]);
    Ok(output.as_slice())
}

fn password_is_saslprep_identity_ascii(password: &[u8]) -> bool {
    password.iter().all(|byte| matches!(*byte, 0x20..=0x7e))
}

fn ensure_rc4_field_lengths(owner: &[u8], user: &[u8]) -> Result<()> {
    if owner.len() != 32 {
        bail!(
            "Encrypt /O should be 32 bytes for revision 2/3/4, not {}",
            owner.len()
        );
    }
    if user.len() != 32 {
        bail!(
            "Encrypt /U should be 32 bytes for revision 2/3/4, not {}",
            user.len()
        );
    }
    Ok(())
}

fn ensure_r56_field_lengths(owner: &[u8], user: &[u8]) -> Result<()> {
    if owner.len() != 48 {
        bail!(
            "Encrypt /O should be 48 bytes for revision 5/6, not {}",
            owner.len()
        );
    }
    if user.len() != 48 {
        bail!(
            "Encrypt /U should be 48 bytes for revision 5/6, not {}",
            user.len()
        );
    }
    Ok(())
}

fn revision_6_kdf_with_scratch(
    password: &[u8],
    salt: &[u8],
    user: &[u8],
    work_buffer: &mut Vec<u8>,
) -> [u8; 32] {
    ensure_revision_6_work_buffer_capacity(work_buffer);
    let data = &mut work_buffer[..MAX_REVISION_6_DATA_LEN];
    let mut data_total_len = 0usize;

    let mut sha256 = Sha256::new();
    let mut sha384 = Sha384::new();
    let mut sha512 = Sha512::new();

    let mut input_sha256 = Sha256::new();
    input_sha256.update(password);
    input_sha256.update(salt);
    input_sha256.update(user);
    let input = input_sha256.finalize();
    let (mut key, mut iv) = input.split();

    let mut block = [0u8; MAX_REVISION_6_BLOCK_LEN];
    let mut block_size = 32usize;
    block[..block_size].copy_from_slice(&input[..block_size]);

    let mut round = 0usize;
    while round < 64 || round < data[data_total_len - 1] as usize + 32 {
        let aes = Aes128CbcEnc::new(&key, &iv);
        let repeated_len = password.len() + block_size + user.len();
        debug_assert!(repeated_len <= MAX_REVISION_6_REPEATED_LEN);

        data[..password.len()].copy_from_slice(password);
        data[password.len()..password.len() + block_size].copy_from_slice(&block[..block_size]);
        data[password.len() + block_size..repeated_len].copy_from_slice(user);
        fill_repeated_prefix_in_place(data, repeated_len, REVISION_6_REPEAT_COUNT);
        data_total_len = repeated_len * REVISION_6_REPEAT_COUNT;

        let encrypted = aes
            .encrypt_padded_mut::<NoPadding>(&mut data[..data_total_len], data_total_len)
            .expect("revision 6 KDF input length must be a multiple of the AES block size");

        let sum: usize = encrypted[..16].iter().map(|byte| *byte as usize).sum();
        block_size = sum % 3 * 16 + 32;
        match block_size {
            32 => {
                sha256.update(encrypted);
                block[..block_size].copy_from_slice(&sha256.finalize_reset());
            }
            48 => {
                sha384.update(encrypted);
                block[..block_size].copy_from_slice(&sha384.finalize_reset());
            }
            64 => {
                sha512.update(encrypted);
                block[..block_size].copy_from_slice(&sha512.finalize_reset());
            }
            _ => unreachable!(),
        }

        key.copy_from_slice(&block[..16]);
        iv.copy_from_slice(&block[16..32]);
        round += 1;
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&block[..32]);
    hash
}

fn ensure_revision_6_work_buffer_capacity(work_buffer: &mut Vec<u8>) {
    if work_buffer.len() < MAX_REVISION_6_DATA_LEN {
        work_buffer.resize(MAX_REVISION_6_DATA_LEN, 0);
    }
}

fn fill_repeated_prefix_in_place(buffer: &mut [u8], prefix_len: usize, repeat_count: usize) {
    debug_assert!(prefix_len > 0);
    debug_assert!(repeat_count > 0);
    debug_assert!(prefix_len.saturating_mul(repeat_count) <= buffer.len());

    let total_len = prefix_len * repeat_count;
    let mut filled_len = prefix_len;
    while filled_len < total_len {
        let copy_len = filled_len.min(total_len - filled_len);
        buffer.copy_within(..copy_len, filled_len);
        filled_len += copy_len;
    }
}

/// A minimal resolver that understands only as much of the PDF object model as
/// is needed to load the security envelope.
///
/// # Responsibilities
///
/// - decode xref streams during bootstrap
/// - resolve indirect `/Encrypt` dictionaries
/// - resolve objects stored inside object streams when required
/// - decode stream filters without any document decryption
///
/// # Deliberate omissions
///
/// This resolver does not support general document traversal and never installs
/// a document decryption key. That is intentional: we only need to extract the
/// pre-authentication envelope required for password checks.
struct SecurityEnvelopeResolver {
    pdf_bytes: Arc<[u8]>,
    start_offset: usize,
    refs: RefCell<Option<XRefTable>>,
    stream_cache: RefCell<HashMap<PlainRef, Arc<[u8]>>>,
    resolution_stack: RefCell<Vec<PlainRef>>,
    options: ParseOptions,
}

impl SecurityEnvelopeResolver {
    /// Creates a new bootstrap resolver before the xref table is known.
    fn new(pdf_bytes: Arc<[u8]>, start_offset: usize) -> Self {
        Self {
            pdf_bytes,
            start_offset,
            refs: RefCell::new(None),
            stream_cache: RefCell::new(HashMap::new()),
            resolution_stack: RefCell::new(Vec::new()),
            options: ParseOptions::strict(),
        }
    }

    /// Installs the resolved xref table after the initial trailer read.
    fn install_refs(&self, refs: XRefTable) {
        *self.refs.borrow_mut() = Some(refs);
    }

    /// Resolves a primitive only when it is an indirect reference.
    fn resolve_optional_reference(&self, primitive: Primitive) -> pdf::error::Result<Primitive> {
        match primitive {
            Primitive::Reference(reference) => self.resolve(reference),
            other => Ok(other),
        }
    }

    /// Resolves the trailer `/Encrypt` entry and tolerates select non-canonical
    /// permission encodings emitted by some third-party writers.
    ///
    /// # Design rationale
    ///
    /// The `pdf` crate models all integer primitives as signed `i32`. Some
    /// generators serialize the Standard Security Handler `/P` field as an
    /// unsigned 32-bit integer carrying the same bit pattern, for example
    /// `4294967292` instead of `-4`. That representation is semantically
    /// equivalent for the permissions bitmask but exceeds the parser's integer
    /// range and prevents the `/Encrypt` dictionary from loading at all.
    ///
    /// Rather than weakening parsing globally, we keep the strict parse as the
    /// first attempt and only retry for the specific indirect `/Encrypt` object
    /// after normalizing `/P` back to its signed 32-bit form.
    fn resolve_encrypt_optional_reference(
        &self,
        primitive: Primitive,
    ) -> pdf::error::Result<Primitive> {
        match primitive {
            Primitive::Reference(reference) => self.resolve_encrypt_reference(reference),
            other => Ok(other),
        }
    }

    /// Resolves the indirect `/Encrypt` dictionary with a targeted compatibility
    /// fallback for non-canonical `/P` values.
    fn resolve_encrypt_reference(&self, reference: PlainRef) -> pdf::error::Result<Primitive> {
        let refs = self.refs.borrow();
        let refs = refs.as_ref().ok_or_else(|| PdfError::Other {
            msg: "xref table has not been initialized".to_string(),
        })?;

        match refs.get(reference.id)? {
            XRef::Raw { pos, .. } => {
                let absolute_offset = self
                    .start_offset
                    .checked_add(pos)
                    .ok_or(PdfError::Invalid)?;
                let object_bytes = self.pdf_bytes.read(absolute_offset..)?;
                self.parse_encrypt_indirect_object(object_bytes, absolute_offset, reference)
            }
            XRef::Stream { stream_id, index } => {
                let object_stream = self.get::<ObjectStream>(Ref::from_id(stream_id))?;
                let (data, range) = object_stream.get_object_slice(index, self)?;
                let slice = data.get(range.clone()).ok_or_else(|| PdfError::Other {
                    msg: format!(
                        "invalid object-stream slice {:?} for {} decoded bytes",
                        range,
                        data.len()
                    ),
                })?;
                self.parse_encrypt_stream_object(slice, reference)
            }
            XRef::Free { .. } => Err(PdfError::FreeObject {
                obj_nr: reference.id,
            }),
            XRef::Promised => Err(PdfError::Other {
                msg: format!("promised reference {:?} is unsupported", reference),
            }),
            XRef::Invalid => Err(PdfError::NullRef {
                obj_nr: reference.id,
            }),
        }
    }

    /// Parses a raw indirect `/Encrypt` object and retries after normalizing a
    /// non-canonical unsigned permissions integer when needed.
    fn parse_encrypt_indirect_object(
        &self,
        object_bytes: &[u8],
        absolute_offset: usize,
        reference: PlainRef,
    ) -> pdf::error::Result<Primitive> {
        let mut lexer = Lexer::with_offset(object_bytes, absolute_offset);
        match parse_indirect_object(&mut lexer, self, None, ParseFlags::ANY) {
            Ok((_, primitive)) => Ok(primitive),
            Err(error) => {
                let Some((normalized_bytes, original_permissions, normalized_permissions)) =
                    normalize_noncanonical_encrypt_permissions_integer(object_bytes)
                else {
                    return Err(error);
                };
                debug!(
                    "cracker.verifier.prepare.normalize_encrypt_permissions ref={} original_permissions={} normalized_permissions={}",
                    reference.id,
                    original_permissions,
                    normalized_permissions
                );

                let mut retry_lexer = Lexer::with_offset(&normalized_bytes, absolute_offset);
                Ok(parse_indirect_object(&mut retry_lexer, self, None, ParseFlags::ANY)?.1)
            }
        }
    }

    /// Parses an object-stream-backed `/Encrypt` dictionary with the same
    /// targeted permissions fallback used for raw indirect objects.
    fn parse_encrypt_stream_object(
        &self,
        object_bytes: &[u8],
        reference: PlainRef,
    ) -> pdf::error::Result<Primitive> {
        match parse(object_bytes, self, ParseFlags::ANY) {
            Ok(primitive) => Ok(primitive),
            Err(error) => {
                let Some((normalized_bytes, original_permissions, normalized_permissions)) =
                    normalize_noncanonical_encrypt_permissions_integer(object_bytes)
                else {
                    return Err(error);
                };
                debug!(
                    "cracker.verifier.prepare.normalize_encrypt_permissions ref={} original_permissions={} normalized_permissions={}",
                    reference.id,
                    original_permissions,
                    normalized_permissions
                );

                parse(&normalized_bytes, self, ParseFlags::ANY)
            }
        }
    }

    /// Reads and decodes a stream range from the backing PDF bytes.
    fn read_stream_data(
        &self,
        id: PlainRef,
        range: Range<usize>,
        filters: &[StreamFilter],
    ) -> pdf::error::Result<Arc<[u8]>> {
        if let Some(cached) = self.stream_cache.borrow().get(&id) {
            return Ok(Arc::clone(cached));
        }

        let mut data = self.pdf_bytes.read(range)?.to_vec();
        for filter in filters {
            data = decode(&data, filter)?;
        }
        let data: Arc<[u8]> = data.into();
        self.stream_cache.borrow_mut().insert(id, Arc::clone(&data));
        Ok(data)
    }

    /// Resolves a raw or object-stream-backed reference without any password.
    fn resolve_object(
        &self,
        reference: PlainRef,
        flags: ParseFlags,
    ) -> pdf::error::Result<Primitive> {
        let refs = self.refs.borrow();
        let refs = refs.as_ref().ok_or_else(|| PdfError::Other {
            msg: "xref table has not been initialized".to_string(),
        })?;

        match refs.get(reference.id)? {
            XRef::Raw { pos, .. } => {
                let absolute_offset = self
                    .start_offset
                    .checked_add(pos)
                    .ok_or(PdfError::Invalid)?;
                let mut lexer =
                    Lexer::with_offset(self.pdf_bytes.read(absolute_offset..)?, absolute_offset);
                Ok(parse_indirect_object(&mut lexer, self, None, flags)?.1)
            }
            XRef::Stream { stream_id, index } => {
                if !flags.contains(ParseFlags::STREAM) {
                    return Err(PdfError::PrimitiveNotAllowed {
                        found: ParseFlags::STREAM,
                        allowed: flags,
                    });
                }

                let object_stream = self.get::<ObjectStream>(Ref::from_id(stream_id))?;
                let (data, range) = object_stream.get_object_slice(index, self)?;
                let slice = data.get(range.clone()).ok_or_else(|| PdfError::Other {
                    msg: format!(
                        "invalid object-stream slice {:?} for {} decoded bytes",
                        range,
                        data.len()
                    ),
                })?;
                parse(slice, self, flags)
            }
            XRef::Free { .. } => Err(PdfError::FreeObject {
                obj_nr: reference.id,
            }),
            XRef::Promised => Err(PdfError::Other {
                msg: format!("promised reference {:?} is unsupported", reference),
            }),
            XRef::Invalid => Err(PdfError::NullRef {
                obj_nr: reference.id,
            }),
        }
    }
}

impl Resolve for SecurityEnvelopeResolver {
    fn resolve_flags(
        &self,
        reference: PlainRef,
        flags: ParseFlags,
        _depth: usize,
    ) -> pdf::error::Result<Primitive> {
        self.resolve_object(reference, flags)
    }

    fn get<T: Object>(&self, reference: Ref<T>) -> pdf::error::Result<RcRef<T>> {
        let key = reference.get_inner();
        {
            let mut stack = self.resolution_stack.borrow_mut();
            if stack.contains(&key) {
                return Err(PdfError::Other {
                    msg: format!("recursive reference while resolving {:?}", key),
                });
            }
            stack.push(key);
        }

        let result = self
            .resolve(key)
            .and_then(|primitive| T::from_primitive(primitive, self))
            .map(|object| RcRef::new(key, Arc::new(object)));

        let popped = self.resolution_stack.borrow_mut().pop();
        debug_assert_eq!(popped, Some(key));
        result
    }

    fn options(&self) -> &ParseOptions {
        &self.options
    }

    fn stream_data(&self, _id: PlainRef, range: Range<usize>) -> pdf::error::Result<Arc<[u8]>> {
        Ok(self.pdf_bytes.read(range)?.to_vec().into())
    }

    fn get_data_or_decode(
        &self,
        id: PlainRef,
        range: Range<usize>,
        filters: &[StreamFilter],
    ) -> pdf::error::Result<Arc<[u8]>> {
        self.read_stream_data(id, range, filters)
    }
}

/// Rewrites a non-canonical unsigned Standard Security Handler `/P` integer
/// into its signed 32-bit representation.
///
/// # Returns
///
/// Returns the normalized bytes together with the original unsigned value and
/// the equivalent signed value when a rewrite was applied. Returns `None` when
/// the source does not contain a normalizable `/P` entry.
///
/// # Design rationale
///
/// Some generators serialize the permissions bitmask as an unsigned decimal
/// representation of the 32-bit field. The PDF security algorithm treats `/P`
/// as a 32-bit signed value, so preserving the exact bit pattern while changing
/// only the textual representation is sufficient to restore compatibility.
fn normalize_noncanonical_encrypt_permissions_integer(
    source: &[u8],
) -> Option<(Vec<u8>, u32, i32)> {
    let mut offset = 0usize;
    while let Some(relative) = source[offset..].iter().position(|byte| *byte == b'/') {
        let key_start = offset + relative;
        let Some(key_end) = key_start.checked_add(2) else {
            return None;
        };
        if source.get(key_start + 1) != Some(&b'P')
            || !source
                .get(key_end)
                .is_some_and(|byte| is_pdf_token_boundary(*byte))
        {
            offset = key_start.saturating_add(1);
            continue;
        }

        let mut number_start = key_end;
        while source
            .get(number_start)
            .is_some_and(|byte| is_pdf_whitespace(*byte))
        {
            number_start += 1;
        }

        if source
            .get(number_start)
            .is_some_and(|byte| *byte == b'+' || *byte == b'-')
        {
            return None;
        }

        let mut number_end = number_start;
        while source
            .get(number_end)
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            number_end += 1;
        }

        if number_end == number_start
            || !source
                .get(number_end)
                .is_none_or(|byte| is_pdf_token_boundary(*byte))
        {
            offset = key_start.saturating_add(1);
            continue;
        }

        let value = std::str::from_utf8(&source[number_start..number_end])
            .ok()?
            .parse::<u64>()
            .ok()?;
        if value <= i32::MAX as u64 || value > u32::MAX as u64 {
            return None;
        }

        let original_permissions = value as u32;
        let normalized_permissions = original_permissions as i32;
        let normalized_text = normalized_permissions.to_string();

        let mut normalized_bytes =
            Vec::with_capacity(source.len() - (number_end - number_start) + normalized_text.len());
        normalized_bytes.extend_from_slice(&source[..number_start]);
        normalized_bytes.extend_from_slice(normalized_text.as_bytes());
        normalized_bytes.extend_from_slice(&source[number_end..]);
        return Some((
            normalized_bytes,
            original_permissions,
            normalized_permissions,
        ));
    }

    None
}

/// Returns `true` when the byte terminates a PDF token.
fn is_pdf_token_boundary(byte: u8) -> bool {
    is_pdf_whitespace(byte) || matches!(byte, b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'%')
}

/// Returns `true` when the byte is PDF whitespace.
fn is_pdf_whitespace(byte: u8) -> bool {
    matches!(byte, 0 | b' ' | b'\r' | b'\n' | b'\t' | 0x0c)
}

/// Extracts the first trailer document identifier.
fn extract_document_id(trailer: &Dictionary) -> Result<Vec<u8>> {
    let document_id = trailer
        .get("ID")
        .ok_or_else(|| anyhow!("Trailer is missing /ID"))?
        .as_array()
        .map_err(anyhow::Error::from)
        .context("Trailer /ID was not an array")?
        .first()
        .ok_or_else(|| anyhow!("Trailer /ID array was empty"))?
        .as_string()
        .map_err(anyhow::Error::from)
        .context("Trailer /ID[0] was not a string")?
        .as_bytes()
        .to_vec();
    Ok(document_id)
}

/// Reads a required integer field from a PDF dictionary.
fn required_u32(dict: &Dictionary, dict_name: &str, key: &str) -> Result<u32> {
    dict.get(key)
        .ok_or_else(|| anyhow!("{} dictionary is missing /{}", dict_name, key))?
        .as_u32()
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{dict_name} /{key} was not an integer"))
}

/// Reads a required signed integer field from a PDF dictionary.
fn required_i32(dict: &Dictionary, dict_name: &str, key: &str) -> Result<i32> {
    dict.get(key)
        .ok_or_else(|| anyhow!("{} dictionary is missing /{}", dict_name, key))?
        .as_integer()
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{dict_name} /{key} was not an integer"))
}

/// Reads a required string field from a PDF dictionary as raw bytes.
fn required_bytes(dict: &Dictionary, dict_name: &str, key: &str) -> Result<Vec<u8>> {
    dict.get(key)
        .ok_or_else(|| anyhow!("{} dictionary is missing /{}", dict_name, key))?
        .as_string()
        .map(|value| value.as_bytes().to_vec())
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{dict_name} /{key} was not a string"))
}

/// Reads a required name field from a PDF dictionary.
fn required_name<'a>(dict: &'a Dictionary, dict_name: &str, key: &str) -> Result<&'a str> {
    dict.get(key)
        .ok_or_else(|| anyhow!("{} dictionary is missing /{}", dict_name, key))?
        .as_name()
        .map_err(anyhow::Error::from)
        .with_context(|| format!("{dict_name} /{key} was not a name"))
}

/// Reads an optional boolean field from a PDF dictionary.
fn optional_bool(dict: &Dictionary, key: &str) -> Result<Option<bool>> {
    dict.get(key)
        .map(|value| {
            value
                .as_bool()
                .map_err(anyhow::Error::from)
                .with_context(|| format!("Encrypt /{key} was not a boolean"))
        })
        .transpose()
}

/// Determines the effective default crypt-filter method for V=4/V=5 files.
fn default_crypt_filter_method(
    resolver: &SecurityEnvelopeResolver,
    encrypt_dict: &Dictionary,
) -> Result<String> {
    let crypt_filters = encrypt_dict
        .get("CF")
        .ok_or_else(|| anyhow!("Encrypt dictionary is missing /CF"))?
        .clone()
        .into_dictionary()
        .map_err(anyhow::Error::from)
        .context("Encrypt /CF was not a dictionary")?;

    let default_filter_name = if let Some(default_filter) = encrypt_dict.get("StmF") {
        default_filter
            .as_name()
            .map_err(anyhow::Error::from)
            .context("Encrypt /StmF was not a name")?
            .to_string()
    } else if crypt_filters.len() == 1 {
        crypt_filters
            .iter()
            .next()
            .map(|(name, _)| name.as_str().to_string())
            .expect("checked len() == 1")
    } else {
        bail!("Encrypt dictionary is missing /StmF and has multiple /CF entries");
    };

    if default_filter_name == "Identity" {
        bail!("Unsupported default crypt filter /Identity");
    }

    let filter_entry = crypt_filters
        .get(default_filter_name.as_str())
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "Encrypt /CF does not contain the default filter /{}",
                default_filter_name
            )
        })?;
    let filter_dict = resolver
        .resolve_optional_reference(filter_entry)
        .map_err(anyhow::Error::from)
        .context("Failed to resolve the default crypt filter dictionary")?
        .into_dictionary()
        .map_err(anyhow::Error::from)
        .context("Default crypt filter entry was not a dictionary")?;

    Ok(filter_dict
        .get("CFM")
        .map(|value| {
            value
                .as_name()
                .map(str::to_string)
                .map_err(anyhow::Error::from)
                .context("Crypt filter /CFM was not a name")
        })
        .transpose()?
        .unwrap_or_else(|| "None".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_standard_security_filters() {
        let mut encrypt = Dictionary::new();
        encrypt.insert("Filter", Primitive::Name("Adobe.PubSec".into()));
        encrypt.insert("V", 5i32);
        encrypt.insert("R", 6i32);

        let resolver = SecurityEnvelopeResolver::new(Arc::from(Vec::<u8>::new()), 0);
        let error = SecurityProfile::from_encrypt_dictionary(&resolver, &encrypt)
            .expect_err("non-standard filters must be rejected");

        assert!(error
            .to_string()
            .contains("Unsupported security handler filter"));
    }

    #[test]
    fn printable_ascii_passwords_use_the_identity_normalization_fast_path() {
        let mut output = Vec::new();
        let normalized = normalize_r56_password_into(b"Hashcat-ish 123!", &mut output)
            .expect("printable ASCII should normalize cleanly");

        assert_eq!(normalized, b"Hashcat-ish 123!");
    }

    #[test]
    fn fill_repeated_prefix_in_place_replicates_by_doubling() {
        let mut buffer = [0u8; 12];
        buffer[..3].copy_from_slice(b"abc");

        fill_repeated_prefix_in_place(&mut buffer, 3, 4);

        assert_eq!(&buffer, b"abcabcabcabc");
    }

    #[test]
    fn revision_6_work_buffer_is_allocated_once_and_reused() {
        let mut scratch = PasswordAttemptScratch::default();

        let first = revision_6_kdf_with_scratch(
            b"pass-r6",
            b"12345678",
            b"",
            &mut scratch.revision_6_work_buffer,
        );
        let first_capacity = scratch.revision_6_work_buffer.len();
        let second = revision_6_kdf_with_scratch(
            b"pass-r6",
            b"87654321",
            b"user-material",
            &mut scratch.revision_6_work_buffer,
        );

        assert_eq!(scratch.revision_6_work_buffer.len(), first_capacity);
        assert_ne!(first, second);
        assert!(first_capacity >= MAX_REVISION_6_DATA_LEN);
    }
}
