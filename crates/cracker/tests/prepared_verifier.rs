use std::{
    fs,
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
const PYPDF_R5_UNSIGNED_PERMISSIONS_PASSWORD: &[u8] = b"user-r5";
const R6_PADDED_VERIFIER_PASSWORD: &[u8] = b"user-r6";
const PYPDF_R5_UNSIGNED_PERMISSIONS_FIXTURE_HEX: &str = concat!(
    "255044462d312e330a25e2e3cfd30a312030206f626a0a3c3c0a2f50726f6475636572203c6363383933396431346339",
    "353562366338356537363336633732656366383262613032656635666137353665306137663330363530616633303465",
    "64356334323e0a3e3e0a656e646f626a0a322030206f626a0a3c3c0a2f54797065202f50616765730a2f436f756e7420",
    "310a2f4b696473205b203420302052205d0a3e3e0a656e646f626a0a332030206f626a0a3c3c0a2f54797065202f4361",
    "74616c6f670a2f50616765732032203020520a3e3e0a656e646f626a0a342030206f626a0a3c3c0a2f54797065202f50",
    "6167650a2f5265736f7572636573203c3c0a3e3e0a2f4d65646961426f78205b20302e3020302e302032303020323030",
    "205d0a2f506172656e742032203020520a3e3e0a656e646f626a0a352030206f626a0a3c3c0a2f5620350a2f5220350a",
    "2f4c656e677468203235360a2f5020343239343936373239320a2f46696c746572202f5374616e646172640a2f4f203c",
    "313761623264656232633563386665376231663333643737396632636535353838303131323137663833616535633866",
    "666363356430363333633761613037373963633664363961646139306236613366316161326136316634333432383761",
    "3e0a2f55203c323661373837363332363938366235363535316439623563313432323233323564623661323634376334",
    "353262626430623339616338396236373939656561316463646163623262656666616230646463646638393561633438",
    "3238303165343e0a2f4346203c3c0a2f5374644346203c3c0a2f417574684576656e74202f446f634f70656e0a2f4346",
    "4d202f41455356330a2f4c656e6774682033320a3e3e0a3e3e0a2f53746d46202f53746443460a2f53747246202f5374",
    "6443460a2f4f45203c636430336463616563653264356363613934373039303832383137376438376532636662343532",
    "336562646436643835616137646533663938616438633662393e0a2f5545203c31663139613337363237353466396635",
    "336532336130396466663431643437353837366337313639356239643235343664356136633731333135303136333366",
    "3e0a2f5065726d73203c37613466663165393035386134366237643430346137363165393632366163383e0a3e3e0a65",
    "6e646f626a0a787265660a3020360a303030303030303030302036353533352066200a30303030303030303135203030",
    "303030206e200a30303030303030313133203030303030206e200a30303030303030313732203030303030206e200a30",
    "303030303030323231203030303030206e200a30303030303030333135203030303030206e200a747261696c65720a3c",
    "3c0a2f53697a6520360a2f526f6f742033203020520a2f496e666f2031203020520a2f4944205b203c33353339363333",
    "323330363236323631363536333338333236353331363233353633333633333633363136323635363633353631363636",
    "3136353636333133313e203c333533393633333233303632363236313635363333383332363533313632333536333336",
    "333336333631363236353636333536313636363136353636333133313e205d0a2f456e63727970742035203020520a3e",
    "3e0a7374617274787265660a3837300a2525454f460a"
);
const R6_PADDED_VERIFIER_FIXTURE_HEX: &str = concat!(
    "255044462d312e370a25bff7a2fe0a312030206f626a0a3c3c202f457874656e73696f6e73203c3c202f41444245203c",
    "3c202f4261736556657273696f6e202f312e37202f457874656e73696f6e4c6576656c2038203e3e203e3e202f506167",
    "6573203220302052202f54797065202f436174616c6f67203e3e0a656e646f626a0a322030206f626a0a3c3c202f436f",
    "756e742031202f4b696473205b203320302052205d202f54797065202f5061676573203e3e0a656e646f626a0a332030",
    "206f626a0a3c3c202f436f6e74656e7473203420302052202f4d65646961426f78205b20302030203330302032303020",
    "5d202f506172656e74203220302052202f5265736f7572636573203c3c202f466f6e74203c3c202f4631203520302052",
    "203e3e203e3e202f54797065202f50616765203e3e0a656e646f626a0a342030206f626a0a3c3c202f4c656e67746820",
    "3830202f46696c746572202f466c6174654465636f6465203e3e0a73747265616d0a334e324c7949172bb1c939ef93ab",
    "eca4887afd9d150a44282dec43aa7b6aa612ded83c9bfd8022b9a4c71ef093fb725dcd0eef73f152b28746173f0e9f5a",
    "3bf77e8ae488f7e232bb0e89f5209e9f5a17656e6473747265616d0a656e646f626a0a352030206f626a0a3c3c202f42",
    "617365466f6e74202f48656c766574696361202f53756274797065202f5479706531202f54797065202f466f6e74203e",
    "3e0a656e646f626a0a362030206f626a0a3c3c202f4346203c3c202f5374644346203c3c202f417574684576656e7420",
    "2f446f634f70656e202f43464d202f4145535633202f4c656e677468203332203e3e203e3e202f46696c746572202f53",
    "74616e64617264202f4c656e67746820323536202f4f20285c3332355c3030372e79697c4f605c3232305c3032305c32",
    "3633765c725c323732305c323232335c3232355c323630704c5c32303459475c3231315c33323125485c3337315c3333",
    "335c3232355c3331345c3031375c3333315c3331365c3033325c3237355c3234313b5c3333375c3334335c3337345c33",
    "37305c3233325c3337374c5c3237355c3235315c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c30303029",
    "202f4f45203c396236316134313935383133646336633830376161616637386261646134346635623265323263656331",
    "323435386139656430313265636135616661383139613e202f50202d34202f5065726d73203c34316339303965616231",
    "636163626261626532313831663765303639383536363e202f522036202f53746d46202f5374644346202f5374724620",
    "2f5374644346202f5520285c3334365c323532332c68265c3236355c3232315c3235335c333731205c3232375c323630",
    "5c3332375c3230355c3031335c3234305c333437395c3335305c313737735c3337305c3231315c3137373856315c3232",
    "325c333230475c333431745c3333315c3332325c3137375c3331305c3030355c3331305c3030305c333530475c323735",
    "39215c3030303d5c3233315c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c",
    "3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c3030305c30303029202f5545203c3532",
    "636130343430383164393038616466343338623630616263626239643863316134353437653832363733326261373135",
    "38376530376466663637643766383e202f562035203e3e0a656e646f626a0a787265660a3020370a3030303030303030",
    "30302036353533352066200a30303030303030303135203030303030206e200a30303030303030313330203030303030",
    "206e200a30303030303030313839203030303030206e200a30303030303030333137203030303030206e200a30303030",
    "303030343637203030303030206e200a30303030303030353337203030303030206e200a747261696c6572203c3c202f",
    "526f6f74203120302052202f53697a652037202f4944205b3c3031356630303233336362633734373663353239626436",
    "6561643962383663303e3c30313566303032333363626337343736633532396264366561643962383663303e5d202f45",
    "6e6372797074203620302052203e3e0a7374617274787265660a313830370a2525454f460a"
);

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

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex fixture should have an even length");
    let mut output = Vec::with_capacity(input.len() / 2);
    for index in (0..input.len()).step_by(2) {
        let byte = u8::from_str_radix(&input[index..index + 2], 16)
            .expect("hex fixture should contain valid bytes");
        output.push(byte);
    }
    output
}

fn write_hex_pdf_fixture(name: &str, hex: &str) -> PathBuf {
    let path = temp_path(name, "pdf");
    fs::write(&path, decode_hex(hex)).expect("hex PDF fixture should write cleanly");
    path
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

#[test]
fn accepts_aes256_fixture_with_unsigned_permissions_encoding() -> anyhow::Result<()> {
    let path = write_hex_pdf_fixture(
        "pypdf-r5-unsigned-permissions",
        PYPDF_R5_UNSIGNED_PERMISSIONS_FIXTURE_HEX,
    );
    let cracker = PDFCracker::from_file_with_mode(
        path.to_string_lossy().as_ref(),
        VerificationMode::UserOnly,
    )?;

    assert_eq!(cracker.revision(), 5);
    assert_eq!(cracker.variant(), "aes256-r5");
    assert_eq!(
        cracker.classify_password(PYPDF_R5_UNSIGNED_PERMISSIONS_PASSWORD)?,
        Some(PasswordKind::User)
    );
    assert_eq!(cracker.classify_password(b"definitely-wrong")?, None);
    assert!(qpdf_password_is_valid(
        &path,
        PYPDF_R5_UNSIGNED_PERMISSIONS_PASSWORD
    )?);

    fs::remove_file(&path)?;
    Ok(())
}

#[test]
fn accepts_aes256_fixture_with_zero_padded_literal_verifier_fields() -> anyhow::Result<()> {
    let path = write_hex_pdf_fixture("r6-padded-verifier-fields", R6_PADDED_VERIFIER_FIXTURE_HEX);
    let cracker = PDFCracker::from_file_with_mode(
        path.to_string_lossy().as_ref(),
        VerificationMode::UserOnly,
    )?;

    assert_eq!(cracker.revision(), 6);
    assert_eq!(cracker.variant(), "aes256-r6");
    assert_eq!(
        cracker.classify_password(R6_PADDED_VERIFIER_PASSWORD)?,
        Some(PasswordKind::User)
    );
    assert_eq!(cracker.classify_password(b"definitely-wrong")?, None);
    assert!(qpdf_password_is_valid(&path, R6_PADDED_VERIFIER_PASSWORD)?);

    fs::remove_file(&path)?;
    Ok(())
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
