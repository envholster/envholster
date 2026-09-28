//! Golden vectors (ENVELOPE-SPEC §11) — HB1 byte-vector tests and the
//! maintainer-invoked vault-fixture generator.
//!
//! The fixtures live under `crates/envholster-core/tests/golden/` and are the
//! interop contract between independent implementations. HB1 fixtures are
//! exact bytes defined in ENVELOPE-SPEC §11.2 and are verified against those
//! definitions here. Vault fixtures are generated ONCE by the `#[ignore]`d
//! generator below (run `cargo test -p envholster-core --release -- --ignored
//! generate_golden_fixtures`) and regenerated only under a re-freeze of the
//! spec.
//!
//! Fixture caveat, stated plainly: the vault-tier2 hardware recipient's wrap
//! blob is a stand-in — a real age file encrypted to a discarded throwaway
//! X25519 key — because CI (and this generator) has no hardware plugin. The
//! blob is byte-shaped exactly like a real wrap (opaque single-recipient age
//! file), yields `NoMatchingKeys` for every fixture identity, and CI never
//! unwraps the hardware path anyway (ENVELOPE-SPEC §11.3: "CI never unwraps
//! it — the hardware path is covered by the standing human hardware
//! checklist"). See tests/golden/vault-tier2/README (`notes.txt`).
//!
//! All fixture secret values are sentinels; nothing real is ever committed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use envholster_mem::SecretBytes;
use secrecy::{ExposeSecret, SecretString};

use crate::constants::DEK_LEN;
use crate::envelope::uuid_from_str;
use crate::hb1;
use crate::record::{CellId, Guarantee, SecretMode, SecretRecord};
use crate::recovery;
use crate::types::{
    Enrollment, EnvName, EnvSelector, Identity, RecipientClass, RecipientEntry, Tier,
};
use crate::ui::{UnlockUi, WrapContext};
use crate::vault::{stage_dek, Vault};
use crate::wrap::wrap_dek;

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

// ---------------------------------------------------------------------------
// HB1 byte vectors (ENVELOPE-SPEC §11.2) — exact bytes, defined in the spec
// ---------------------------------------------------------------------------

// One parameter per HB1 record field, in the frozen on-disk order (plan/02 §4 /
// ENVELOPE-SPEC §11.2). A struct would obscure the 1:1 mapping between the
// argument list and the spec's field sequence in this generator-only helper.
#[allow(clippy::too_many_arguments)]
fn put_record(
    out: &mut Vec<u8>,
    name: &str,
    tier: u8,
    mode: u8,
    guarantee: u8,
    created: i64,
    updated: i64,
    rotated: i64,
    rotate_after: Option<i64>,
    meta: &[(&str, &[u8])],
    value: &[u8],
) {
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(tier);
    out.push(mode);
    out.push(guarantee);
    out.extend_from_slice(&created.to_le_bytes());
    out.extend_from_slice(&updated.to_le_bytes());
    out.extend_from_slice(&rotated.to_le_bytes());
    match rotate_after {
        Some(seconds) => {
            out.push(1);
            out.extend_from_slice(&seconds.to_le_bytes());
        }
        None => out.push(0),
    }
    out.extend_from_slice(&(meta.len() as u16).to_le_bytes());
    for (key, value) in meta {
        out.extend_from_slice(&(key.len() as u16).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

const T0: i64 = 1767225600; // 2026-01-01T00:00:00Z (ENVELOPE-SPEC §11)

fn alpha_record_bytes(out: &mut Vec<u8>) {
    put_record(out, "ALPHA", 1, 1, 0, T0, T0, T0, None, &[], b"alpha");
}

fn beta_record_bytes(out: &mut Vec<u8>, provider_twice: bool) {
    let meta: Vec<(&str, &[u8])> = if provider_twice {
        vec![
            ("envholster.needs-rotation", b"1" as &[u8]),
            ("provider", b"example"),
            ("provider", b"example"),
        ]
    } else {
        vec![
            ("envholster.needs-rotation", b"1" as &[u8]),
            ("provider", b"example"),
        ]
    };
    put_record(
        out,
        "BETA",
        1,
        3,
        5,
        T0,
        T0 + 1,
        T0 + 2,
        Some(7776000),
        &meta,
        &[0x00, 0xff, 0x10],
    );
}

/// `hb1/two-records.bin`, exactly as ENVELOPE-SPEC §11.2 spells it: 154 bytes.
fn two_records_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&2u32.to_le_bytes());
    alpha_record_bytes(&mut out);
    beta_record_bytes(&mut out, false);
    assert_eq!(out.len(), 154, "spec pins two-records.bin at 154 bytes");
    out
}

/// The annotation text committed as `two-records.fields.txt` (restates the
/// ENVELOPE-SPEC §11.2 field-by-field breakdown).
const TWO_RECORDS_FIELDS: &str = "\
two-records.bin — ENVELOPE-SPEC §11.2, field by field (154 bytes)

02 00 00 00                                        record_count = 2

; record 1 — name \"ALPHA\"
05 00                                              name_len = 5
41 4c 50 48 41                                     \"ALPHA\"
01                                                 tier = 1
01                                                 mode = 1 (env-var)
00                                                 guarantee = 0 (unassigned)
00 b9 55 69 00 00 00 00                            created_at = 1767225600
00 b9 55 69 00 00 00 00                            updated_at = 1767225600
00 b9 55 69 00 00 00 00                            rotated_at = 1767225600
00                                                 ra_flag = 0 (no rotate_after)
00 00                                              meta_count = 0
05 00 00 00                                        value_len = 5
61 6c 70 68 61                                     value = \"alpha\"

; record 2 — name \"BETA\"
04 00                                              name_len = 4
42 45 54 41                                        \"BETA\"
01                                                 tier = 1
03                                                 mode = 3 (api-key)
05                                                 guarantee = 5 (injected-env)
00 b9 55 69 00 00 00 00                            created_at = 1767225600
01 b9 55 69 00 00 00 00                            updated_at = 1767225601
02 b9 55 69 00 00 00 00                            rotated_at = 1767225602
01                                                 ra_flag = 1
00 a7 76 00 00 00 00 00                            rotate_after = 7776000
02 00                                              meta_count = 2
19 00                                              key_len = 25
65 6e 76 68 6f 6c 73 74 65 72 2e 6e 65 65 64 73
2d 72 6f 74 61 74 69 6f 6e                         \"envholster.needs-rotation\"
01 00 00 00                                        value_len = 1
31                                                 \"1\"
08 00                                              key_len = 8
70 72 6f 76 69 64 65 72                            \"provider\"
07 00 00 00                                        value_len = 7
65 78 61 6d 70 6c 65                               \"example\"
03 00 00 00                                        value_len = 3
00 ff 10                                           value (binary)
";

fn hb1_fixture_files() -> Vec<(&'static str, Vec<u8>)> {
    let two = two_records_bytes();

    // bad-unsorted.bin: the two records swapped.
    let mut unsorted = Vec::new();
    unsorted.extend_from_slice(&2u32.to_le_bytes());
    beta_record_bytes(&mut unsorted, false);
    alpha_record_bytes(&mut unsorted);

    // bad-dup-name.bin: two records both named ALPHA.
    let mut dup_name = Vec::new();
    dup_name.extend_from_slice(&2u32.to_le_bytes());
    alpha_record_bytes(&mut dup_name);
    alpha_record_bytes(&mut dup_name);

    // bad-dup-meta.bin: record 2 with `provider` listed twice.
    let mut dup_meta = Vec::new();
    dup_meta.extend_from_slice(&2u32.to_le_bytes());
    alpha_record_bytes(&mut dup_meta);
    beta_record_bytes(&mut dup_meta, true);

    // bad-tier-mismatch.bin: record 1's tier byte set to 02
    // (count 4 + name_len 2 + name 5 = offset 11).
    let mut tier_mismatch = two.clone();
    tier_mismatch[11] = 0x02;

    // bad-flag.bin: record 1's ra_flag set to 02 (offset 11 + 3 + 24 = 38).
    let mut bad_flag = two.clone();
    assert_eq!(bad_flag[38], 0x00, "ra_flag offset drifted");
    bad_flag[38] = 0x02;

    // bad-trailing.bin: one trailing 00 byte.
    let mut trailing = two.clone();
    trailing.push(0x00);

    vec![
        ("empty-cell.bin", vec![0, 0, 0, 0]),
        ("two-records.bin", two),
        ("bad-unsorted.bin", unsorted),
        ("bad-dup-name.bin", dup_name),
        ("bad-dup-meta.bin", dup_meta),
        ("bad-tier-mismatch.bin", tier_mismatch),
        ("bad-flag.bin", bad_flag),
        ("bad-trailing.bin", trailing),
    ]
}

fn read_fixture(rel: &str) -> Vec<u8> {
    let path = golden_dir().join(rel);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "golden fixture {} unreadable ({e}); regenerate with \
             `cargo test -p envholster-core --release -- --ignored generate_golden_fixtures`",
            path.display()
        )
    })
}

#[test]
fn hb1_committed_fixtures_match_their_spec_definitions() {
    for (name, expected) in hb1_fixture_files() {
        let committed = read_fixture(&format!("hb1/{name}"));
        assert_eq!(
            committed, expected,
            "hb1/{name} drifted from ENVELOPE-SPEC §11.2"
        );
    }
    assert_eq!(
        read_fixture("hb1/two-records.fields.txt"),
        TWO_RECORDS_FIELDS.as_bytes(),
        "two-records.fields.txt drifted"
    );
}

#[test]
fn hb1_empty_cell_golden_round_trip() {
    let bytes = read_fixture("hb1/empty-cell.bin");
    let records = hb1::parse(&SecretBytes::try_from_slice(&bytes).unwrap(), Tier::Ambient).unwrap();
    assert!(records.is_empty());
    let re = hb1::encode(&records, Tier::Ambient).unwrap();
    re.with_exposed(|b| assert_eq!(b, &bytes[..]));
}

#[test]
fn hb1_two_records_golden_round_trip() {
    let bytes = read_fixture("hb1/two-records.bin");
    let records = hb1::parse(&SecretBytes::try_from_slice(&bytes).unwrap(), Tier::Ambient).unwrap();
    assert_eq!(records.len(), 2);

    let alpha = &records["ALPHA"];
    assert_eq!(alpha.mode, SecretMode::EnvVar);
    assert_eq!(alpha.guarantee, Guarantee::Unassigned);
    assert_eq!(
        (alpha.created_at, alpha.updated_at, alpha.rotated_at),
        (T0, T0, T0)
    );
    assert_eq!(alpha.rotate_after, None);
    assert!(!alpha.needs_rotation);
    assert!(alpha.metadata.is_empty());
    alpha.value.with_exposed(|v| assert_eq!(v, b"alpha"));

    let beta = &records["BETA"];
    assert_eq!(beta.mode, SecretMode::ApiKey);
    assert_eq!(beta.guarantee, Guarantee::InjectedEnv);
    assert_eq!(
        (beta.created_at, beta.updated_at, beta.rotated_at),
        (T0, T0 + 1, T0 + 2)
    );
    assert_eq!(beta.rotate_after, Some(7776000));
    assert!(beta.needs_rotation, "reserved entry pops into the field");
    assert_eq!(beta.metadata.len(), 1);
    assert_eq!(beta.metadata["provider"], "example");
    beta.value
        .with_exposed(|v| assert_eq!(v, &[0x00, 0xff, 0x10][..]));

    // Round-trip requirement: parse → re-encode reproduces the bytes exactly.
    let re = hb1::encode(&records, Tier::Ambient).unwrap();
    re.with_exposed(|b| assert_eq!(b, &bytes[..], "re-encode is not byte-identical"));
}

#[test]
fn hb1_negative_vectors_are_rejected() {
    for name in [
        "bad-unsorted.bin",
        "bad-dup-name.bin",
        "bad-dup-meta.bin",
        "bad-tier-mismatch.bin",
        "bad-flag.bin",
        "bad-trailing.bin",
    ] {
        let bytes = read_fixture(&format!("hb1/{name}"));
        assert!(
            hb1::parse(&SecretBytes::try_from_slice(&bytes).unwrap(), Tier::Ambient).is_err(),
            "hb1/{name} must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Minimal bech32 encoder (BIP-173, Bech32 variant) — generator-only, used to
// synthesize the vault-tier2 plugin recipient encodings and shared with the
// types.rs identity-parse tests (pub(crate)): it takes any HRP, so the same
// encoder mints age1yubikey/age1se recipients and AGE-PLUGIN-*-1 identities.
// Test code, std only.
// ---------------------------------------------------------------------------

pub(crate) mod bech32 {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    fn polymod(values: &[u8]) -> u32 {
        let mut chk: u32 = 1;
        for &v in values {
            let b = chk >> 25;
            chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
            for (i, g) in GEN.iter().enumerate() {
                if (b >> i) & 1 == 1 {
                    chk ^= g;
                }
            }
        }
        chk
    }

    fn hrp_expand(hrp: &str) -> Vec<u8> {
        let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
        out.push(0);
        out.extend(hrp.bytes().map(|b| b & 31));
        out
    }

    fn to_5bit(data: &[u8]) -> Vec<u8> {
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        let mut out = Vec::new();
        for &b in data {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(((acc >> bits) & 31) as u8);
            }
        }
        if bits > 0 {
            out.push(((acc << (5 - bits)) & 31) as u8);
        }
        out
    }

    pub fn encode(hrp: &str, data: &[u8]) -> String {
        let d5 = to_5bit(data);
        let mut values = hrp_expand(hrp);
        values.extend_from_slice(&d5);
        values.extend_from_slice(&[0u8; 6]);
        let plm = polymod(&values) ^ 1;
        let mut out = String::from(hrp);
        out.push('1');
        for v in &d5 {
            out.push(CHARSET[*v as usize] as char);
        }
        for i in 0..6 {
            out.push(CHARSET[((plm >> (5 * (5 - i))) & 31) as usize] as char);
        }
        out
    }
}

#[test]
fn synthetic_plugin_encoding_parses_and_round_trips() {
    let encoded = bech32::encode("age1yubikey", &[0x42u8; 32]);
    let recipient: age::plugin::Recipient = encoded.parse().expect("bech32 encoder is valid");
    assert_eq!(recipient.plugin(), "yubikey");
    assert_eq!(recipient.to_string(), encoded);

    // The age1se TWIN: Secure Enclave is a first-class peer to YubiKey, so the
    // synthetic-encoding guarantee must hold for both allowlisted plugins. 33
    // bytes — the byte length of a compressed P-256 point, which is what the
    // real age-plugin-se recipient encodes.
    let se_encoded = bech32::encode("age1se", &[0x42u8; 33]);
    let se_recipient: age::plugin::Recipient =
        se_encoded.parse().expect("bech32 encoder is valid for se");
    assert_eq!(se_recipient.plugin(), "se");
    assert_eq!(se_recipient.to_string(), se_encoded);
}

// ---------------------------------------------------------------------------
// Vault fixture generator (maintainer-invoked; ENVELOPE-SPEC §11.3–11.4)
// ---------------------------------------------------------------------------

/// Answers every secret prompt with the fixture passphrase.
struct FixedPassphraseUi(&'static str);

impl UnlockUi for FixedPassphraseUi {
    fn message(&self, _message: &str) {}
    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        Some(true)
    }
    fn input(&self, _description: &str) -> Option<String> {
        None
    }
    fn secret(&self, _description: &str) -> Option<SecretString> {
        Some(SecretString::from(self.0.to_owned()))
    }
}

const FIXTURE_PASSPHRASE: &str = "golden-fixture-passphrase-do-not-reuse";

struct GenKey {
    secret: String,
    entry: RecipientEntry,
}

fn gen_key(class: RecipientClass, label: &str, enrollment: Enrollment) -> GenKey {
    let identity = age::x25519::Identity::generate();
    let entry = RecipientEntry::from_encoded(
        &identity.to_public().to_string(),
        class,
        label.to_owned(),
        enrollment,
    )
    .unwrap();
    GenKey {
        secret: identity.to_string().expose_secret().to_owned(),
        entry,
    }
}

impl GenKey {
    fn identity(&self) -> Identity {
        Identity::X25519(self.secret.parse().unwrap())
    }
}

fn all(max_tier: Tier) -> Enrollment {
    Enrollment(EnvSelector::All { max_tier })
}

fn cell(env: &str, tier: Tier) -> CellId {
    CellId {
        env: EnvName::parse(env).unwrap(),
        tier,
    }
}

fn sentinel_record(value: &[u8], mode: SecretMode) -> SecretRecord {
    SecretRecord {
        value: SecretBytes::try_from_slice(value).unwrap(),
        mode,
        guarantee: Guarantee::Unassigned,
        created_at: T0,
        updated_at: T0,
        rotated_at: T0,
        rotate_after: None,
        needs_rotation: false,
        metadata: BTreeMap::new(),
    }
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
}

/// Builds one fixture vault in `work`, then copies vault + blob into
/// `out_dir` and decrypts the blob to produce the committed `expected.json`.
fn finalize_fixture(work_vault: &Path, out_dir: &Path, recovery_key: &GenKey) -> Vec<u8> {
    let vault_bytes = std::fs::read(work_vault).unwrap();
    let blob_path = work_vault.with_file_name(format!(
        "{}.recovery.age",
        work_vault.file_name().unwrap().to_string_lossy()
    ));
    let blob_bytes = std::fs::read(&blob_path).unwrap();

    write_file(&out_dir.join("secrets.holster"), &vault_bytes);
    write_file(&out_dir.join("secrets.holster.recovery.age"), &blob_bytes);

    // expected.json = the blob plaintext, byte-exact (sentinel values only —
    // this is precisely what the CI cold-recovery drill byte-compares).
    let json = recovery::decrypt_blob(&blob_bytes, &recovery_key.identity()).unwrap();
    let plain = json.with_exposed(|j| j.to_vec());
    write_file(&out_dir.join("expected.json"), &plain);
    write_file(
        &out_dir.join("recovery.identity"),
        format!("{}\n", recovery_key.secret).as_bytes(),
    );
    vault_bytes
}

fn temp_workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "envholster-golden-gen-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Regenerates every committed fixture under tests/golden/. Run explicitly:
/// `cargo test -p envholster-core --release -- --ignored generate_golden_fixtures`
/// Fixtures regenerate only under a re-freeze of ENVELOPE-SPEC/RECOVERY-SPEC.
#[test]
#[ignore = "maintainer-invoked golden-fixture generator (ENVELOPE-SPEC §11)"]
fn generate_golden_fixtures() {
    let golden = golden_dir();

    // --- hb1/ (bytes fully defined by the spec) ---
    for (name, bytes) in hb1_fixture_files() {
        write_file(&golden.join("hb1").join(name), &bytes);
    }
    write_file(
        &golden.join("hb1/two-records.fields.txt"),
        TWO_RECORDS_FIELDS.as_bytes(),
    );

    // --- vault-basic (generation 3; also the cold-recovery-drill fixture) ---
    let basic_recovery = gen_key(
        RecipientClass::Recovery,
        "golden recovery",
        all(Tier::Critical),
    );
    let basic_software = gen_key(
        RecipientClass::Software,
        "golden software",
        all(Tier::Ambient),
    );
    let basic_text;
    {
        let work = temp_workdir("basic");
        let vault_path = work.join("secrets.holster");
        let ctx = WrapContext::silent();
        let mut vault = Vault::testing_create_unsaved(
            &vault_path,
            vec![basic_recovery.entry.clone(), basic_software.entry.clone()],
            uuid_from_str("3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55").unwrap(),
        )
        .unwrap();
        vault.testing_set_saved_at(T0);

        let base1 = cell("base", Tier::Ambient);
        let prod1 = cell("prod", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.unlock_cell(&prod1, &[], &ctx).unwrap();
        vault
            .add_secret(
                &base1,
                "ALPHA",
                sentinel_record(b"golden-alpha-value", SecretMode::EnvVar),
            )
            .unwrap();
        let mut api_key = sentinel_record(b"golden-api-key-value", SecretMode::ApiKey);
        api_key.rotate_after = Some(7776000);
        api_key
            .metadata
            .insert("provider".to_owned(), "example".to_owned());
        vault.add_secret(&prod1, "API_KEY", api_key).unwrap();
        let mut db_password = sentinel_record(b"golden-db-password", SecretMode::ApiKey);
        db_password.needs_rotation = true;
        vault
            .add_secret(&prod1, "DB_PASSWORD", db_password)
            .unwrap();

        vault.save().unwrap(); // 1
        vault.save().unwrap(); // 2
        vault.save().unwrap(); // 3
        assert_eq!(vault.generation(), 3);
        drop(vault);

        let out = golden.join("vault-basic");
        let vault_bytes = finalize_fixture(&vault_path, &out, &basic_recovery);
        write_file(
            &out.join("software.identity"),
            format!("{}\n", basic_software.secret).as_bytes(),
        );
        basic_text = String::from_utf8(vault_bytes).unwrap();
    }

    // --- vault-named (generation 1; named-list enrollment scoping) ---
    {
        let recovery_key = gen_key(
            RecipientClass::Recovery,
            "golden recovery",
            all(Tier::Critical),
        );
        let mut named = BTreeMap::new();
        named.insert(EnvName::parse("dev").unwrap(), Tier::Ambient);
        named.insert(EnvName::parse("prod").unwrap(), Tier::Ambient);
        let software = gen_key(
            RecipientClass::Software,
            "golden software",
            Enrollment(EnvSelector::Named(named)),
        );

        let work = temp_workdir("named");
        let vault_path = work.join("secrets.holster");
        let ctx = WrapContext::silent();
        let mut vault = Vault::testing_create_unsaved(
            &vault_path,
            vec![recovery_key.entry.clone(), software.entry.clone()],
            uuid_from_str("6e1a44d0-52c3-4b6e-9f10-2ab34cd5e601").unwrap(),
        )
        .unwrap();
        vault.testing_set_saved_at(T0);

        let dev1 = cell("dev", Tier::Ambient);
        let staging1 = cell("staging", Tier::Ambient);
        vault.unlock_cell(&dev1, &[], &ctx).unwrap();
        vault.unlock_cell(&staging1, &[], &ctx).unwrap(); // recovery-only wraps
        vault
            .add_secret(
                &dev1,
                "DEV_TOKEN",
                sentinel_record(b"golden-dev-token", SecretMode::ApiKey),
            )
            .unwrap();
        vault
            .add_secret(
                &staging1,
                "STG_TOKEN",
                sentinel_record(b"golden-stg-token", SecretMode::ApiKey),
            )
            .unwrap();
        vault.save().unwrap();
        assert_eq!(vault.generation(), 1);
        drop(vault);

        let out = golden.join("vault-named");
        finalize_fixture(&vault_path, &out, &recovery_key);
        write_file(
            &out.join("software.identity"),
            format!("{}\n", software.secret).as_bytes(),
        );
    }

    // --- vault-scrypt (generation 1; passphrase path, log_n = 20) ---
    {
        let recovery_key = gen_key(
            RecipientClass::Recovery,
            "golden recovery",
            all(Tier::Critical),
        );
        let scrypt_entry =
            RecipientEntry::scrypt("golden passphrase".to_owned(), all(Tier::Ambient), 20).unwrap();

        let work = temp_workdir("scrypt");
        let vault_path = work.join("secrets.holster");
        let ctx = WrapContext::new(std::sync::Arc::new(FixedPassphraseUi(FIXTURE_PASSPHRASE)));
        let mut vault = Vault::testing_create_unsaved(
            &vault_path,
            vec![recovery_key.entry.clone(), scrypt_entry],
            uuid_from_str("9c02b7aa-30e1-4d7f-8b44-5cd6ef017a22").unwrap(),
        )
        .unwrap();
        vault.testing_set_saved_at(T0);

        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault
            .add_secret(
                &base1,
                "SCRYPT_SECRET",
                sentinel_record(b"golden-scrypt-value", SecretMode::Generic),
            )
            .unwrap();
        vault.save().unwrap();
        assert_eq!(vault.generation(), 1);
        drop(vault);

        let out = golden.join("vault-scrypt");
        finalize_fixture(&vault_path, &out, &recovery_key);
        write_file(
            &out.join("passphrase.txt"),
            format!("{FIXTURE_PASSPHRASE}\n").as_bytes(),
        );
    }

    // --- vault-tier2 (generation 1; the wrap matrix on disk, G-A) ---
    {
        let recovery_key = gen_key(
            RecipientClass::Recovery,
            "golden recovery",
            all(Tier::Critical),
        );
        let software = gen_key(
            RecipientClass::Software,
            "golden software",
            all(Tier::Ambient),
        );
        // Synthetic yubikey recipient (see the module doc caveat): a
        // syntactically valid plugin encoding whose wrap blobs are stand-ins.
        let hardware_encoding = bech32::encode("age1yubikey", &[0x42u8; 32]);
        let hardware = RecipientEntry::from_encoded(
            &hardware_encoding,
            RecipientClass::Hardware,
            "golden yubikey".to_owned(),
            all(Tier::Critical),
        )
        .unwrap();
        // The age1se TWIN, under the identical caveat: Secure Enclave is a
        // first-class peer to YubiKey, so the fixture vault carries BOTH
        // hardware plugins side by side — wraps disambiguated by recipient id,
        // never by the shared piv-p256 stanza label. 33 bytes = a compressed
        // P-256 point, the real plugin's recipient payload. NOTE: the
        // COMMITTED vault-tier2 fixture predates this recipient and
        // regenerates only under a spec re-freeze (§11.3); this generator is
        // the frozen intent for that regeneration.
        let se_encoding = bech32::encode("age1se", &[0x24u8; 33]);
        let se_hardware = RecipientEntry::from_encoded(
            &se_encoding,
            RecipientClass::Hardware,
            "golden se".to_owned(),
            all(Tier::Critical),
        )
        .unwrap();
        // The throwaway key that "is" the hardware for wrap purposes; its
        // secret half is dropped on the floor, so nothing can unwrap these
        // blobs — exactly like real hardware absent from CI. Shared by both
        // plugin recipients: the property that matters (`NoMatchingKeys` for
        // every fixture identity) is identical either way.
        let throwaway = age::x25519::Identity::generate();

        let work = temp_workdir("tier2");
        let vault_path = work.join("secrets.holster");
        let ctx = WrapContext::silent();
        let mut vault = Vault::testing_create_unsaved(
            &vault_path,
            vec![
                recovery_key.entry.clone(),
                software.entry.clone(),
                hardware.clone(),
                se_hardware.clone(),
            ],
            uuid_from_str("d41f09b3-77c5-4a02-9e88-10fedc32ab55").unwrap(),
        )
        .unwrap();
        vault.testing_set_saved_at(T0);

        let prod1 = cell("prod", Tier::Ambient);
        let prod2 = cell("prod", Tier::Sensitive);
        for (cell_id, wrap_entries) in [
            (&prod1, vec![&recovery_key.entry, &software.entry]),
            (&prod2, vec![&recovery_key.entry]),
        ] {
            let dek = SecretBytes::try_random(DEK_LEN).unwrap();
            let staged = stage_dek(&dek);
            let mut wraps = Vec::new();
            for entry in wrap_entries {
                wraps.push((entry.id.clone(), wrap_dek(&staged, entry, &ctx).unwrap()));
            }
            // Hardware stand-in wraps (real single-recipient age blobs), one
            // per plugin recipient.
            for plugin_entry in [&hardware, &se_hardware] {
                wraps.push((
                    plugin_entry.id.clone(),
                    age::encrypt(&throwaway.to_public(), &staged[..]).unwrap(),
                ));
            }
            drop(staged);
            vault.testing_insert_unlocked_cell(cell_id.clone(), dek, wraps);
        }
        vault
            .add_secret(
                &prod1,
                "LOW",
                sentinel_record(b"golden-low-value", SecretMode::Generic),
            )
            .unwrap();
        vault
            .add_secret(
                &prod2,
                "HIGH",
                sentinel_record(b"golden-high-value", SecretMode::Generic),
            )
            .unwrap();
        vault.save().unwrap();
        assert_eq!(vault.generation(), 1);
        drop(vault);

        let out = golden.join("vault-tier2");
        finalize_fixture(&vault_path, &out, &recovery_key);
        write_file(
            &out.join("software.identity"),
            format!("{}\n", software.secret).as_bytes(),
        );
        write_file(
            &out.join("notes.txt"),
            b"The hardware recipient's wrap blobs are STAND-INS: real single-recipient\n\
              binary age files encrypted to a throwaway X25519 key whose secret half was\n\
              discarded at generation time (no hardware plugin exists in CI; the hardware\n\
              unwrap path is covered by the standing human hardware checklist -\n\
              ENVELOPE-SPEC \xc2\xa711.3). Byte-shape and unwrap-loop behavior (NoMatchingKeys\n\
              for every fixture identity) are identical to a real plugin wrap.\n",
        );
    }

    // --- negative/ (ENVELOPE-SPEC §11.4; derived from vault-basic) ---
    {
        let negative = golden.join("negative");
        let text = &basic_text;
        let put =
            |name: &str, content: String| write_file(&negative.join(name), content.as_bytes());

        put(
            "schema2.holster",
            text.replacen("schema = 1", "schema = 2", 1),
        );
        put(
            "unknown-kind.holster",
            text.replacen("kind = x25519", "kind = mlkem768", 1),
        );
        put(
            "unknown-plugin.holster",
            text.replacen("kind = x25519", "kind = plugin:tpm", 1),
        );
        put(
            "mixed-wildcard.holster",
            text.replacen("enroll = *:1", "enroll = *:1,dev:1", 1),
        );
        put(
            "noncanonical-header.holster",
            text.replacen("schema = 1", "schema  = 1", 1),
        );
        put(
            "tampered-generation.holster",
            text.replacen("generation = 3", "generation = 4", 1),
        );
        put(
            "bad-commitment.holster",
            flip_first_commitment_hex_char(text),
        );
        put("tampered-body.holster", flip_first_body_char(text));
        put("trailing-bytes.holster", format!("{text}\n"));

        // dup-recipient.holster: the first recipient block duplicated
        // verbatim (equal ids violate strict ascending order).
        let first_block = extract_first_recipient_block(text);
        let dup = text.replacen(&first_block, &format!("{first_block}{first_block}"), 1);
        assert_ne!(dup, *text, "failed to duplicate a recipient block");
        put("dup-recipient.holster", dup);

        // swapped-cells.holster: from a purpose-built variant of vault-basic
        // whose two cells carry equal-length plaintexts; tag + body swapped.
        let work = temp_workdir("swapped");
        let vault_path = work.join("secrets.holster");
        let ctx = WrapContext::silent();
        let mut vault = Vault::testing_create_unsaved(
            &vault_path,
            vec![basic_recovery.entry.clone(), basic_software.entry.clone()],
            uuid_from_str("3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55").unwrap(),
        )
        .unwrap();
        vault.testing_set_saved_at(T0);
        let base1 = cell("base", Tier::Ambient);
        let dev1 = cell("dev", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.unlock_cell(&dev1, &[], &ctx).unwrap();
        vault
            .add_secret(&base1, "A", sentinel_record(b"xx", SecretMode::Generic))
            .unwrap();
        vault
            .add_secret(&dev1, "B", sentinel_record(b"yy", SecretMode::Generic))
            .unwrap();
        vault.save().unwrap();
        drop(vault);
        let variant = std::fs::read_to_string(&vault_path).unwrap();
        put("swapped-cells.holster", swap_cells(&variant));
    }

    // Sanity: everything just written passes the committed-fixture checks.
    hb1_committed_fixtures_match_their_spec_definitions();
}

/// Extracts the first `[recipient ...]` block (leading blank line through the
/// enroll line) for duplication.
fn extract_first_recipient_block(text: &str) -> String {
    let start = text.find("\n[recipient ").expect("recipient block");
    let enroll = text[start..].find("\nenroll = ").expect("enroll line") + start;
    let end = text[enroll + 1..].find('\n').expect("enroll LF") + enroll + 1;
    text[start..=end].to_owned()
}

/// Replaces one ASCII byte of `text` at `at` (the file is ASCII throughout).
fn replace_byte_at(text: &str, at: usize, new: u8) -> String {
    let mut bytes = text.as_bytes().to_vec();
    bytes[at] = new;
    String::from_utf8(bytes).expect("header text is ASCII")
}

/// Flips the first hex char of the first `commitment = ` value.
fn flip_first_commitment_hex_char(text: &str) -> String {
    let at = text.find("commitment = ").expect("commitment line") + "commitment = ".len();
    let old = text.as_bytes()[at];
    replace_byte_at(text, at, if old == b'0' { b'1' } else { b'0' })
}

/// Flips the first base64 char of the first body block (same length, still
/// canonical base64 — a leading character of a 64-char line).
fn flip_first_body_char(text: &str) -> String {
    let heading = text.find("\n[body ").expect("body block");
    let line_start = text[heading + 1..].find('\n').expect("body heading LF") + heading + 2;
    let old = text.as_bytes()[line_start];
    replace_byte_at(text, line_start, if old == b'A' { b'B' } else { b'A' })
}

/// Swaps the tag values and body contents of the two cells of the variant
/// vault (equal ct-len by construction).
fn swap_cells(text: &str) -> String {
    // Tags: `tag base:1 = <hex>` / `tag dev:1 = <hex>`.
    let tag_value = |prefix: &str| -> String {
        let at = text.find(prefix).expect("tag line") + prefix.len();
        text[at..at + 32].to_owned()
    };
    let tag_a = tag_value("tag base:1 = ");
    let tag_b = tag_value("tag dev:1 = ");

    // Bodies: the base64 lines between each heading and the next boundary.
    let body_of = |heading: &str| -> (usize, usize) {
        let start = text.find(heading).expect("body heading") + heading.len();
        let rest = &text[start..];
        let end = rest.find("\n\n").map(|e| e + 1).unwrap_or(rest.len());
        (start, start + end)
    };
    let (a_start, a_end) = body_of("[body \"base\" 1]\n");
    let (b_start, b_end) = body_of("[body \"dev\" 1]\n");
    assert!(a_end <= b_start, "cell order");
    let body_a = text[a_start..a_end].to_owned();
    let body_b = text[b_start..b_end].to_owned();
    assert_eq!(body_a.len(), body_b.len(), "equal ct-len by construction");

    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..a_start]);
    out.push_str(&body_b);
    out.push_str(&text[a_end..b_start]);
    out.push_str(&body_a);
    out.push_str(&text[b_end..]);
    out.replacen(
        &format!("tag base:1 = {tag_a}"),
        &format!("tag base:1 = {tag_b}"),
        1,
    )
    .replacen(
        &format!("tag dev:1 = {tag_b}"),
        &format!("tag dev:1 = {tag_a}"),
        1,
    )
}
