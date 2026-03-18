use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use cracker::{PDFCracker, PDFCrackerState, PasswordKind, VerificationMode};

struct Fixture {
    file: &'static str,
    user_password: &'static [u8],
    owner_password: &'static [u8],
    revision: u32,
    variant: &'static str,
    encrypt_metadata: bool,
}

const R5_UNICODE_USER_PASSWORD: &[u8] = &[0x70, 0xc3, 0xa4, 0x73, 0x73, 0x2d, 0x72, 0x35];
const R6_UNICODE_USER_PASSWORD: &[u8] = &[0x70, 0xc3, 0xa4, 0x73, 0x73, 0x2d, 0x72, 0x36];

const MATRIX: &[Fixture] = &[
    Fixture {
        file: "r2-rc4.pdf",
        user_password: b"user-r2",
        owner_password: b"owner-r2",
        revision: 2,
        variant: "rc4-r2",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r3-rc4.pdf",
        user_password: b"user-r3",
        owner_password: b"owner-r3",
        revision: 3,
        variant: "rc4-r3",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r4-rc4.pdf",
        user_password: b"user-r4",
        owner_password: b"owner-r4",
        revision: 4,
        variant: "rc4-r4",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r4-aes128.pdf",
        user_password: b"user-r4a",
        owner_password: b"owner-r4a",
        revision: 4,
        variant: "aes128-r4",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r5-aes256.pdf",
        user_password: b"user-r5",
        owner_password: b"owner-r5",
        revision: 5,
        variant: "aes256-r5",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r6-aes256.pdf",
        user_password: b"user-r6",
        owner_password: b"owner-r6",
        revision: 6,
        variant: "aes256-r6",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r5-aes256-unicode.pdf",
        user_password: R5_UNICODE_USER_PASSWORD,
        owner_password: b"owner-r5u",
        revision: 5,
        variant: "aes256-r5",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r6-aes256-unicode.pdf",
        user_password: R6_UNICODE_USER_PASSWORD,
        owner_password: b"owner-r6u",
        revision: 6,
        variant: "aes256-r6",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r4-aes128-object-streams.pdf",
        user_password: b"user-r4os",
        owner_password: b"owner-r4os",
        revision: 4,
        variant: "aes128-r4",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r4-aes128-linearized.pdf",
        user_password: b"user-r4lin",
        owner_password: b"owner-r4lin",
        revision: 4,
        variant: "aes128-r4",
        encrypt_metadata: true,
    },
    Fixture {
        file: "r4-aes128-cleartext-metadata.pdf",
        user_password: b"user-r4meta",
        owner_password: b"owner-r4meta",
        revision: 4,
        variant: "aes128-r4",
        encrypt_metadata: false,
    },
];

fn fixture_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(file)
}

fn example_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join(file)
}

fn prepared_cracker(file: &str) -> anyhow::Result<PDFCracker> {
    prepared_cracker_with_mode(file, VerificationMode::default())
}

fn prepared_cracker_with_mode(
    file: &str,
    verification_mode: VerificationMode,
) -> anyhow::Result<PDFCracker> {
    let path = fixture_path(file);
    PDFCracker::from_file_with_mode(path.to_string_lossy().as_ref(), verification_mode)
}

fn temp_path(name: &str, extension: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "pdfrip-{name}-{}-{unique}.{extension}",
        std::process::id()
    ))
}

fn qpdf_env_enabled() -> bool {
    std::env::var_os("PDFRIP_QPDF_TESTS").is_some()
}

fn qpdf_password(password: &[u8]) -> String {
    String::from_utf8(password.to_vec()).expect("fixture passwords should stay valid utf-8")
}

fn qpdf_show_encryption(path: &Path, password: &[u8]) -> anyhow::Result<String> {
    let output = Command::new("qpdf")
        .arg("--show-encryption")
        .arg(format!("--password={}", qpdf_password(password)))
        .arg(path)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "qpdf --show-encryption failed for '{}' with status {:?}: {}",
            path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8(output.stdout).expect("qpdf output should be valid utf-8"))
}

fn qpdf_password_is_valid(path: &Path, password: &[u8]) -> anyhow::Result<bool> {
    let output = Command::new("qpdf")
        .arg(format!("--password={}", qpdf_password(password)))
        .arg("--check")
        .arg(path)
        .output()?;
    Ok(output.status.success())
}

fn qpdf_revision(output: &str) -> u32 {
    output
        .lines()
        .find_map(|line| line.strip_prefix("R = "))
        .expect("qpdf output should contain a revision line")
        .trim()
        .parse::<u32>()
        .expect("qpdf revision should parse as an integer")
}

fn qpdf_file_encryption_method(output: &str) -> Option<&str> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("file encryption method: "))
        .map(str::trim)
}

fn expected_qpdf_method(variant: &str) -> &'static str {
    match variant {
        "rc4-r2" | "rc4-r3" | "rc4-r4" => "RC4",
        "aes128-r4" => "AESv2",
        "aes256-r5" | "aes256-r6" => "AESv3",
        other => panic!("unexpected verifier variant '{other}'"),
    }
}

#[test]
fn accepts_user_and_owner_passwords_across_supported_revisions() -> anyhow::Result<()> {
    for fixture in MATRIX {
        let cracker = prepared_cracker(fixture.file)?;
        assert_eq!(
            cracker.revision(),
            fixture.revision,
            "expected revision for {}",
            fixture.file
        );
        assert_eq!(
            cracker.variant(),
            fixture.variant,
            "expected variant for {}",
            fixture.file
        );
        assert_eq!(
            cracker.encrypt_metadata(),
            fixture.encrypt_metadata,
            "expected /EncryptMetadata classification for {}",
            fixture.file
        );

        let mut user_state = PDFCrackerState::from_cracker(&cracker)?;
        assert!(
            user_state.attempt(fixture.user_password),
            "expected user password to verify for {}",
            fixture.file
        );
        assert_eq!(
            cracker.classify_password(fixture.user_password)?,
            Some(PasswordKind::User),
            "expected user password classification for {}",
            fixture.file
        );

        let mut owner_state = PDFCrackerState::from_cracker(&cracker)?;
        assert!(
            owner_state.attempt(fixture.owner_password),
            "expected owner password to verify for {}",
            fixture.file
        );
        assert_eq!(
            cracker.classify_password(fixture.owner_password)?,
            Some(PasswordKind::Owner),
            "expected owner password classification for {}",
            fixture.file
        );
    }

    Ok(())
}

#[test]
fn user_only_mode_accepts_user_passwords_and_rejects_owner_only_passwords() -> anyhow::Result<()> {
    for fixture in MATRIX {
        let cracker = prepared_cracker_with_mode(fixture.file, VerificationMode::UserOnly)?;

        let mut user_state = PDFCrackerState::from_cracker(&cracker)?;
        assert!(
            user_state.attempt(fixture.user_password),
            "expected user-only mode to accept the user password for {}",
            fixture.file
        );
        assert_eq!(
            cracker.classify_password(fixture.user_password)?,
            Some(PasswordKind::User),
            "expected user-only mode to report the user password for {}",
            fixture.file
        );

        let mut owner_state = PDFCrackerState::from_cracker(&cracker)?;
        assert!(
            !owner_state.attempt(fixture.owner_password),
            "expected user-only mode to reject the owner password for {}",
            fixture.file
        );
        assert_eq!(
            cracker.classify_password(fixture.owner_password)?,
            None,
            "expected user-only mode to suppress owner-password classification for {}",
            fixture.file
        );
    }

    Ok(())
}

#[test]
fn rejects_wrong_passwords_and_allows_state_reuse() -> anyhow::Result<()> {
    for fixture in MATRIX {
        let cracker = prepared_cracker(fixture.file)?;
        let mut state = PDFCrackerState::from_cracker(&cracker)?;

        assert!(
            !state.attempt(b"definitely-wrong-password"),
            "wrong password unexpectedly matched {}",
            fixture.file
        );
        assert!(
            state.attempt(fixture.user_password),
            "state reuse failed for {}",
            fixture.file
        );
        assert!(
            !state.attempt(b"still-wrong"),
            "post-success wrong password unexpectedly matched {}",
            fixture.file
        );
    }

    Ok(())
}

#[test]
fn qpdf_oracle_matches_prepared_verifier_metadata_and_password_validity() -> anyhow::Result<()> {
    if !qpdf_env_enabled() {
        return Ok(());
    }

    for fixture in MATRIX {
        let path = fixture_path(fixture.file);
        let cracker = prepared_cracker(fixture.file)?;

        let qpdf_user = qpdf_show_encryption(&path, fixture.user_password)?;
        assert_eq!(qpdf_revision(&qpdf_user), fixture.revision);
        if let Some(method) = qpdf_file_encryption_method(&qpdf_user) {
            assert_eq!(method, expected_qpdf_method(fixture.variant));
        } else {
            assert!(matches!(fixture.revision, 2 | 3));
            assert!(fixture.variant.starts_with("rc4-"));
        }

        let qpdf_owner = qpdf_show_encryption(&path, fixture.owner_password)?;
        assert_eq!(qpdf_revision(&qpdf_owner), fixture.revision);
        if let Some(method) = qpdf_file_encryption_method(&qpdf_owner) {
            assert_eq!(method, expected_qpdf_method(fixture.variant));
        } else {
            assert!(matches!(fixture.revision, 2 | 3));
            assert!(fixture.variant.starts_with("rc4-"));
        }

        assert!(
            qpdf_password_is_valid(&path, fixture.user_password)?,
            "qpdf rejected known user password for {}",
            fixture.file
        );
        assert!(
            qpdf_password_is_valid(&path, fixture.owner_password)?,
            "qpdf rejected known owner password for {}",
            fixture.file
        );
        assert!(
            !qpdf_password_is_valid(&path, b"definitely-wrong-password")?,
            "qpdf unexpectedly accepted wrong password for {}",
            fixture.file
        );

        assert_eq!(
            cracker.classify_password(fixture.user_password)?,
            Some(PasswordKind::User),
            "prepared verifier user classification drifted for {}",
            fixture.file
        );
        assert_eq!(
            cracker.classify_password(fixture.owner_password)?,
            Some(PasswordKind::Owner),
            "prepared verifier owner classification drifted for {}",
            fixture.file
        );
        assert_eq!(
            cracker.classify_password(b"definitely-wrong-password")?,
            None,
            "prepared verifier wrong-password classification drifted for {}",
            fixture.file
        );
    }

    let blank_path = fixture_path("r4-aes128-blank-user.pdf");
    let blank_cracker = prepared_cracker("r4-aes128-blank-user.pdf")?;
    assert!(qpdf_password_is_valid(&blank_path, b"")?);
    assert_eq!(
        blank_cracker.classify_password(b"")?,
        Some(PasswordKind::User)
    );

    Ok(())
}

#[test]
fn verifier_preparation_ignores_corrupted_non_security_objects() -> anyhow::Result<()> {
    let source = fixture_path("r4-aes128.pdf");
    let temp = temp_path("verifier-non-security-corruption", "pdf");
    let mut bytes = std::fs::read(&source)?;
    let needle = b"/Helvetica";
    let replacement = b"/Xelvetixa";
    assert_eq!(needle.len(), replacement.len());

    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture should contain the expected font object name");
    bytes[offset..offset + needle.len()].copy_from_slice(replacement);
    std::fs::write(&temp, bytes)?;

    let cracker = PDFCracker::from_file(temp.to_string_lossy().as_ref())?;
    let mut state = PDFCrackerState::from_cracker(&cracker)?;
    assert!(state.attempt(b"user-r4a"));

    std::fs::remove_file(temp)?;
    Ok(())
}

#[test]
fn bundled_aes256_examples_prepare_as_expected_revisions() -> anyhow::Result<()> {
    let r5 = PDFCracker::from_file(
        example_path("passwords_aes_256.pdf")
            .to_string_lossy()
            .as_ref(),
    )?;
    assert_eq!(r5.revision(), 5);
    assert_eq!(r5.variant(), "aes256-r5");

    let r6 = PDFCracker::from_file(
        example_path("passwords_aes_256_hardened.pdf")
            .to_string_lossy()
            .as_ref(),
    )?;
    assert_eq!(r6.revision(), 6);
    assert_eq!(r6.variant(), "aes256-r6");

    Ok(())
}

#[test]
fn supports_blank_user_passwords_without_special_case_loading() -> anyhow::Result<()> {
    let cracker = prepared_cracker("r4-aes128-blank-user.pdf")?;
    assert_eq!(cracker.revision(), 4);
    assert_eq!(cracker.variant(), "aes128-r4");
    assert!(cracker.encrypt_metadata());

    let mut blank_state = PDFCrackerState::from_cracker(&cracker)?;
    assert!(blank_state.attempt(b""));
    assert_eq!(cracker.classify_password(b"")?, Some(PasswordKind::User));

    let mut owner_state = PDFCrackerState::from_cracker(&cracker)?;
    assert!(owner_state.attempt(b"owner-blank"));

    let mut wrong_state = PDFCrackerState::from_cracker(&cracker)?;
    assert!(!wrong_state.attempt(b"owner-blank-typo"));

    Ok(())
}

#[test]
fn rejects_unencrypted_pdfs_during_preparation() {
    let error = match prepared_cracker("source-minimal.pdf") {
        Ok(_) => panic!("unencrypted fixtures must fail closed during preparation"),
        Err(error) => error,
    };

    let rendered_error = format!("{error:#}");
    assert!(
        rendered_error.contains("not encrypted with the Standard password-based security handler"),
        "unexpected error: {rendered_error}"
    );
}
