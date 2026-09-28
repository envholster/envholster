//! Golden-vector round-trip tests (ENVELOPE-SPEC §11; RECOVERY-SPEC §7) over
//! the crate's PUBLIC API, against the committed fixtures under
//! `tests/golden/`. Byte reads and comparisons use std only; the age/AEAD
//! operations go through the crate's own regular dependencies (the golden
//! rule, ENVELOPE-SPEC §11).
//!
//! Fixtures are copied into per-test temp directories before opening: opening
//! a vault takes the advisory flock (a sidecar file), which must never appear
//! inside the committed fixture tree.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use envholster_core::{
    CellId, CoreError, EnvName, Identity, RecipientClass, Tier, Vault, WrapContext,
};

const T0: i64 = 1767225600;

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// Copies every file of a fixture directory into a fresh temp dir.
fn stage_fixture(fixture: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dst = std::env::temp_dir().join(format!(
        "envholster-golden-{}-{}-{}",
        std::process::id(),
        fixture.replace('/', "-"),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dst).unwrap();
    let src = golden_dir().join(fixture);
    for entry in std::fs::read_dir(&src).unwrap_or_else(|e| {
        panic!(
            "fixture dir {} unreadable ({e}); regenerate with `cargo test -p \
             envholster-core --release -- --ignored generate_golden_fixtures`",
            src.display()
        )
    }) {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    dst
}

/// Stages one negative vector beside the vault-basic identities.
fn stage_negative(name: &str) -> PathBuf {
    let dir = stage_fixture("vault-basic");
    std::fs::copy(
        golden_dir().join("negative").join(name),
        dir.join("secrets.holster"),
    )
    .unwrap();
    dir
}

fn identity_from(path: &Path) -> Identity {
    let text = std::fs::read_to_string(path).unwrap();
    Identity::X25519(text.trim().parse().unwrap())
}

fn cell(env: &str, tier: Tier) -> CellId {
    CellId {
        env: EnvName::parse(env).unwrap(),
        tier,
    }
}

// ---------------------------------------------------------------------------
// vault-basic — the whole envelope round-trip plus recovery lockstep
// ---------------------------------------------------------------------------

/// The RECOVERY-SPEC §3.1 canonical single-line form — the frozen logical
/// content of vault-basic, restated here so the committed expected.json, the
/// committed blob, AND the live vault all pin against the spec text itself.
const VAULT_BASIC_EXPECTED_JSON: &str = concat!(
    "{\"envs\":{\"base\":{\"1\":{\"ALPHA\":{\"created_at\":1767225600,",
    "\"guarantee\":\"unassigned\",\"metadata\":{},\"mode\":\"env-var\",",
    "\"rotated_at\":1767225600,\"updated_at\":1767225600,",
    "\"value\":\"Z29sZGVuLWFscGhhLXZhbHVl\"}}},\"prod\":{\"1\":{",
    "\"API_KEY\":{\"created_at\":1767225600,\"guarantee\":\"unassigned\",",
    "\"metadata\":{\"provider\":\"example\"},\"mode\":\"api-key\",",
    "\"rotate_after\":7776000,\"rotated_at\":1767225600,",
    "\"updated_at\":1767225600,\"value\":\"Z29sZGVuLWFwaS1rZXktdmFsdWU=\"},",
    "\"DB_PASSWORD\":{\"created_at\":1767225600,\"guarantee\":\"unassigned\",",
    "\"metadata\":{\"envholster.needs-rotation\":\"1\"},\"mode\":\"api-key\",",
    "\"rotated_at\":1767225600,\"updated_at\":1767225600,",
    "\"value\":\"Z29sZGVuLWRiLXBhc3N3b3Jk\"}}}},\"generation\":3,",
    "\"saved_at\":1767225600,\"schema\":1,",
    "\"vault_uuid\":\"3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55\"}"
);

#[test]
fn vault_basic_expected_json_matches_recovery_spec_example() {
    let committed = std::fs::read(golden_dir().join("vault-basic/expected.json")).unwrap();
    assert_eq!(
        committed,
        VAULT_BASIC_EXPECTED_JSON.as_bytes(),
        "vault-basic/expected.json drifted from the RECOVERY-SPEC §3.1 example"
    );
}

#[test]
fn vault_basic_opens_and_round_trips_via_software_identity() {
    let dir = stage_fixture("vault-basic");
    let mut vault = Vault::open(&dir.join("secrets.holster")).unwrap();
    assert_eq!(vault.generation(), 3);
    assert_eq!(vault.recipients().len(), 2);

    let ctx = WrapContext::silent();
    let software = identity_from(&dir.join("software.identity"));
    let base1 = cell("base", Tier::Ambient);
    let prod1 = cell("prod", Tier::Ambient);
    vault
        .unlock_cell(&base1, std::slice::from_ref(&software), &ctx)
        .unwrap();
    vault
        .unlock_cell(&prod1, std::slice::from_ref(&software), &ctx)
        .unwrap();

    let alpha = vault.get_secret(&base1, "ALPHA").unwrap();
    alpha
        .value
        .with_exposed(|v| assert_eq!(v, b"golden-alpha-value"));
    assert_eq!(
        (alpha.created_at, alpha.updated_at, alpha.rotated_at),
        (T0, T0, T0)
    );

    let api_key = vault.get_secret(&prod1, "API_KEY").unwrap();
    api_key
        .value
        .with_exposed(|v| assert_eq!(v, b"golden-api-key-value"));
    assert_eq!(api_key.rotate_after, Some(7776000));
    assert_eq!(api_key.metadata["provider"], "example");

    let db_password = vault.get_secret(&prod1, "DB_PASSWORD").unwrap();
    db_password
        .value
        .with_exposed(|v| assert_eq!(v, b"golden-db-password"));
    assert!(db_password.needs_rotation);
    assert!(
        db_password.metadata.is_empty(),
        "reserved entry pops into the field"
    );
}

#[test]
fn vault_basic_recovery_identity_reaches_everything() {
    let dir = stage_fixture("vault-basic");
    let mut vault = Vault::open(&dir.join("secrets.holster")).unwrap();
    let ctx = WrapContext::silent();
    let recovery = identity_from(&dir.join("recovery.identity"));
    for c in [cell("base", Tier::Ambient), cell("prod", Tier::Ambient)] {
        vault
            .unlock_cell(&c, std::slice::from_ref(&recovery), &ctx)
            .unwrap();
    }
    assert_eq!(vault.list().len(), 3);
}

#[test]
fn vault_basic_recovery_blob_is_lockstep_and_decrypts_to_expected_json() {
    // The CI cold-recovery drill, minus the clean container: decrypt the
    // committed blob (armored age; the crate's own age dependency stands in
    // for the CLI) and byte-compare to expected.json (RECOVERY-SPEC §7).
    let dir = golden_dir().join("vault-basic");
    let armored = std::fs::read(dir.join("secrets.holster.recovery.age")).unwrap();
    let text = std::str::from_utf8(&armored).unwrap();
    assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----\n"));
    assert!(!text.contains('\r'));

    let identity_text = std::fs::read_to_string(dir.join("recovery.identity")).unwrap();
    let identity: age::x25519::Identity = identity_text.trim().parse().unwrap();
    let decryptor =
        age::Decryptor::new_buffered(age::armor::ArmoredReader::new(&armored[..])).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut plain = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut plain).unwrap();
    assert_eq!(plain, VAULT_BASIC_EXPECTED_JSON.as_bytes());

    // Lockstep check with no envholster code (RECOVERY-SPEC §7 step 4): the
    // plain-text generation/vault-uuid header lines match the blob.
    let vault_text = std::fs::read_to_string(dir.join("secrets.holster")).unwrap();
    assert!(vault_text.contains("\ngeneration = 3\n"));
    assert!(vault_text.contains("\nvault-uuid = 3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55\n"));

    // And through the public API: recovery_test proves the whole path.
    let staged = stage_fixture("vault-basic");
    let vault = Vault::open(&staged.join("secrets.holster")).unwrap();
    vault
        .recovery_test(
            &[identity_from(&staged.join("recovery.identity"))],
            &WrapContext::silent(),
        )
        .unwrap();
}

#[test]
fn recovery_test_detects_blob_drift() {
    // Swap in vault-named's blob: same format, wrong uuid/generation.
    let dir = stage_fixture("vault-basic");
    std::fs::copy(
        golden_dir().join("vault-named/secrets.holster.recovery.age"),
        dir.join("secrets.holster.recovery.age"),
    )
    .unwrap();
    let vault = Vault::open(&dir.join("secrets.holster")).unwrap();
    // vault-named's blob is encrypted to a DIFFERENT recovery identity, so
    // this surfaces as a decrypt failure — still a hard error, never a pass.
    assert!(vault
        .recovery_test(
            &[identity_from(&dir.join("recovery.identity"))],
            &WrapContext::silent(),
        )
        .is_err());
}

// ---------------------------------------------------------------------------
// vault-named — enrollment scoping is cryptographic, not cosmetic
// ---------------------------------------------------------------------------

#[test]
fn vault_named_enrollment_scoping_is_per_cell() {
    let dir = stage_fixture("vault-named");
    let mut vault = Vault::open(&dir.join("secrets.holster")).unwrap();
    assert_eq!(vault.generation(), 1);
    let ctx = WrapContext::silent();
    let software = identity_from(&dir.join("software.identity"));
    let dev1 = cell("dev", Tier::Ambient);
    let staging1 = cell("staging", Tier::Ambient);

    // The software identity unwraps dev…
    vault
        .unlock_cell(&dev1, std::slice::from_ref(&software), &ctx)
        .unwrap();
    vault
        .get_secret(&dev1, "DEV_TOKEN")
        .unwrap()
        .value
        .with_exposed(|v| assert_eq!(v, b"golden-dev-token"));

    // …and ends in "no matching identity" on staging (not enrolled there).
    assert!(matches!(
        vault.unlock_cell(&staging1, std::slice::from_ref(&software), &ctx),
        Err(CoreError::NoMatchingIdentity { env, tier: 1, saw_wrong_passphrase: false })
            if env == "staging"
    ));

    // Recovery unwraps both.
    let recovery = identity_from(&dir.join("recovery.identity"));
    vault
        .unlock_cell(&staging1, std::slice::from_ref(&recovery), &ctx)
        .unwrap();
    vault
        .get_secret(&staging1, "STG_TOKEN")
        .unwrap()
        .value
        .with_exposed(|v| assert_eq!(v, b"golden-stg-token"));

    // The staging cell's floor is Recovery — no software wrap exists (G-A
    // consequence surfaced by status).
    let staging_status = vault
        .cells()
        .into_iter()
        .find(|s| s.id == staging1)
        .unwrap();
    assert_eq!(staging_status.floor, RecipientClass::Recovery);
}

// ---------------------------------------------------------------------------
// vault-scrypt — the passphrase path and its work-factor posture
// ---------------------------------------------------------------------------

#[test]
fn vault_scrypt_unwraps_under_the_work_cap_and_classifies_wrong_passphrase() {
    let dir = stage_fixture("vault-scrypt");
    let passphrase = std::fs::read_to_string(dir.join("passphrase.txt")).unwrap();
    let base1 = cell("base", Tier::Ambient);
    let ctx = WrapContext::silent();

    // Wrong passphrase: §6.3 loop classification — continue + re-prompt
    // hint, never an abort.
    let mut vault = Vault::open(&dir.join("secrets.holster")).unwrap();
    let wrong = Identity::Scrypt(secrecy::SecretString::from("not-the-passphrase".to_owned()));
    assert!(matches!(
        vault.unlock_cell(&base1, &[wrong], &ctx),
        Err(CoreError::NoMatchingIdentity {
            saw_wrong_passphrase: true,
            ..
        })
    ));

    // Correct passphrase unwraps under the fixed decrypt-side cap.
    let good = Identity::Scrypt(secrecy::SecretString::from(
        passphrase.trim_end().to_owned(),
    ));
    vault.unlock_cell(&base1, &[good], &ctx).unwrap();
    vault
        .get_secret(&base1, "SCRYPT_SECRET")
        .unwrap()
        .value
        .with_exposed(|v| assert_eq!(v, b"golden-scrypt-value"));

    // The scrypt recipient block carries kind scrypt:20 and NO encoding line
    // (ENVELOPE-SPEC §4.4, Appendix A.1).
    let text = std::fs::read_to_string(dir.join("secrets.holster")).unwrap();
    assert!(text.contains("kind = scrypt:20"));
    let scrypt_block = text
        .split("\n\n")
        .find(|block| block.contains("kind = scrypt:20"))
        .unwrap();
    assert!(
        !scrypt_block.contains("encoding"),
        "scrypt blocks omit the encoding line entirely"
    );
}

// ---------------------------------------------------------------------------
// vault-tier2 — the wrap-matrix gate (G-A): the P0 headline test
// ---------------------------------------------------------------------------

#[test]
fn wrap_matrix_gate_software_identity_cannot_unwrap_tier2_cell() {
    let dir = stage_fixture("vault-tier2");
    let mut vault = Vault::open(&dir.join("secrets.holster")).unwrap();
    let ctx = WrapContext::silent();
    let software = identity_from(&dir.join("software.identity"));
    let prod1 = cell("prod", Tier::Ambient);
    let prod2 = cell("prod", Tier::Sensitive);

    // On disk, the tier-2 cell block carries NO wrap for the software
    // recipient — the matrix is structural, visible in plaintext.
    let text = std::fs::read_to_string(dir.join("secrets.holster")).unwrap();
    let software_id = {
        // The software recipient's block id: the block whose enroll is *:1.
        let block = text
            .split("\n\n")
            .find(|b| b.starts_with("[recipient ") && b.contains("class = software"))
            .unwrap();
        block
            .lines()
            .next()
            .unwrap()
            .trim_start_matches("[recipient \"")
            .trim_end_matches("\"]")
            .to_owned()
    };
    let tier2_block = text
        .split("\n\n")
        .find(|b| b.starts_with("[cell \"prod\" 2]"))
        .expect("tier-2 cell block");
    assert!(
        !tier2_block.contains(&software_id),
        "a tier-2 cell must never carry a software wrap (G-A)"
    );
    let tier1_block = text
        .split("\n\n")
        .find(|b| b.starts_with("[cell \"prod\" 1]"))
        .expect("tier-1 cell block");
    assert!(
        tier1_block.contains(&software_id),
        "the tier-1 cell does wrap to the software recipient"
    );

    // Cryptographically: the software (X25519 identity-file, enrolled tier 1)
    // identity opens (prod, 1)…
    vault
        .unlock_cell(&prod1, std::slice::from_ref(&software), &ctx)
        .unwrap();
    vault
        .get_secret(&prod1, "LOW")
        .unwrap()
        .value
        .with_exposed(|v| assert_eq!(v, b"golden-low-value"));

    // …and CANNOT unwrap the tier-2 cell: the unwrap loop exhausts.
    assert!(matches!(
        vault.unlock_cell(&prod2, std::slice::from_ref(&software), &ctx),
        Err(CoreError::NoMatchingIdentity { env, tier: 2, .. }) if env == "prod"
    ));

    // The recovery identity opens both (always *:3).
    let recovery = identity_from(&dir.join("recovery.identity"));
    vault
        .unlock_cell(&prod2, std::slice::from_ref(&recovery), &ctx)
        .unwrap();
    vault
        .get_secret(&prod2, "HIGH")
        .unwrap()
        .value
        .with_exposed(|v| assert_eq!(v, b"golden-high-value"));
}

#[test]
fn vault_tier2_recovery_blob_covers_the_tier2_cell() {
    // The recovery blob must include the tier-2 cell wrapped to recovery
    // only — proven by extracting HIGH from the blob with vanilla age
    // semantics (RECOVERY-SPEC: the disaster path reaches EVERY tier).
    let dir = golden_dir().join("vault-tier2");
    let armored = std::fs::read(dir.join("secrets.holster.recovery.age")).unwrap();
    let identity_text = std::fs::read_to_string(dir.join("recovery.identity")).unwrap();
    let identity: age::x25519::Identity = identity_text.trim().parse().unwrap();
    let decryptor =
        age::Decryptor::new_buffered(age::armor::ArmoredReader::new(&armored[..])).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut plain = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut plain).unwrap();
    let json = std::str::from_utf8(&plain).unwrap();
    assert_eq!(plain, std::fs::read(dir.join("expected.json")).unwrap());
    // "golden-high-value" base64 = Z29sZGVuLWhpZ2gtdmFsdWU=
    assert!(json.contains(
        "\"2\":{\"HIGH\":{\"created_at\":1767225600,\"guarantee\":\"unassigned\",\
         \"metadata\":{},\"mode\":\"generic\",\"rotated_at\":1767225600,\
         \"updated_at\":1767225600,\"value\":\"Z29sZGVuLWhpZ2gtdmFsdWU=\"}}"
    ));
}

// ---------------------------------------------------------------------------
// Negative vault vectors (ENVELOPE-SPEC §11.4) — each MUST fail as stated
// ---------------------------------------------------------------------------

#[test]
fn negative_vectors_fail_before_cryptography() {
    let open = |name: &str| {
        let dir = stage_negative(name);
        Vault::open(&dir.join("secrets.holster"))
    };

    assert!(matches!(
        open("schema2.holster"),
        Err(CoreError::UnsupportedSchema {
            found: 2,
            supported: 1
        })
    ));
    assert!(matches!(
        open("unknown-kind.holster"),
        Err(CoreError::UnknownRecipientKind { kind }) if kind == "mlkem768"
    ));
    assert!(matches!(
        open("unknown-plugin.holster"),
        Err(CoreError::PluginNotAllowed(name)) if name == "tpm"
    ));
    for parse_error in [
        "dup-recipient.holster",
        "mixed-wildcard.holster",
        "noncanonical-header.holster",
        "trailing-bytes.holster",
    ] {
        assert!(
            matches!(open(parse_error), Err(CoreError::HeaderParse { .. })),
            "{parse_error} must be a parse error"
        );
    }
}

#[test]
fn negative_vectors_fail_decryption_with_valid_identities() {
    // These parse canonically but MUST fail authenticated decryption, with
    // the indistinguishable AeadFailed outcome (tag vs commitment — §5.4).
    let unlock = |name: &str, env: &str| {
        let dir = stage_negative(name);
        let mut vault = Vault::open(&dir.join("secrets.holster")).unwrap();
        let software = identity_from(&dir.join("software.identity"));
        vault.unlock_cell(
            &cell(env, Tier::Ambient),
            &[software],
            &WrapContext::silent(),
        )
    };

    for (name, env) in [
        ("tampered-generation.holster", "base"),
        ("tampered-body.holster", "base"),
        ("bad-commitment.holster", "base"),
    ] {
        assert!(
            matches!(unlock(name, env), Err(CoreError::AeadFailed { .. })),
            "{name} must fail as AeadFailed"
        );
    }

    // swapped-cells: two equal-ct-len bodies exchanged — BOTH cells fail.
    let dir = stage_negative("swapped-cells.holster");
    for env in ["base", "dev"] {
        let mut vault = Vault::open(&dir.join("secrets.holster")).unwrap();
        let software = identity_from(&dir.join("software.identity"));
        assert!(
            matches!(
                vault.unlock_cell(
                    &cell(env, Tier::Ambient),
                    &[software],
                    &WrapContext::silent(),
                ),
                Err(CoreError::AeadFailed { .. })
            ),
            "swapped cell {env} must fail decryption (AAD cell suffix)"
        );
        drop(vault);
    }
}
