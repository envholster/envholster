//! Frozen constants (plan/04-contracts §4.5, c50). Names verbatim.

pub const BIN_CLI: &str = "envholster";

pub const MANIFEST_FILENAME: &str = "envholster.toml";
pub const VAULT_FILENAME: &str = "secrets.holster";
pub const RECOVERY_FILENAME: &str = "secrets.holster.recovery.age";

pub const VAULT_MAGIC: &[u8; 12] = b"ENVHOLSTERv1";
pub const SCHEMA: u32 = 1;

pub const DEK_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const COMMIT_LEN: usize = 32;

pub const DEK_COMMIT_CONTEXT: &[u8] = b"envholster-v1-commit";
/// AAD grammar: plan/02-envelope.
pub const AAD_CELL_PREFIX: &str = "cell:";

/// The HB1 mode byte (plan/02-envelope §5).
pub const MODE_GENERIC: u8 = 0;
pub const MODE_ENV_VAR: u8 = 1;
pub const MODE_SSH_KEY: u8 = 2;
pub const MODE_API_KEY: u8 = 3;

/// The HB1 guarantee byte (plan/02-envelope §5; G-number = D5 taxonomy,
/// plan/06-brokers).
pub const GUARANTEE_UNASSIGNED: u8 = 0;
pub const GUARANTEE_G_MIN: u8 = 1;
pub const GUARANTEE_G_MAX: u8 = 5;

/// Reserved HB1 metadata keys (plan/04-contracts §4.3).
pub const METADATA_RESERVED_PREFIX: &str = "envholster.";
pub const METADATA_KEY_NEEDS_ROTATION: &str = "envholster.needs-rotation";
/// AEAD-protected SecretRecord.metadata flag: "true" ⇒ this ssh-key is served
/// by the standing agent socket (Workstream B). Authoritative — the manifest
/// mirror is documentation only (manifest is attacker-editable; ALL record
/// metadata rides inside the sealed record, so any key here is AEAD-protected).
///
/// Deliberately NOT under `METADATA_RESERVED_PREFIX`: schema 1 freezes the
/// reserved namespace to exactly `METADATA_KEY_NEEDS_ROTATION` (ENVELOPE-SPEC
/// §7.2, Appendix A.10 — writers reject other reserved keys and parsers refuse
/// them without a schema bump), so this flag travels as ordinary caller
/// metadata under a name the CLI owns.
pub const METADATA_KEY_SHARED_AGENT: &str = "shared-agent";

pub const ENV_VAR_PREFIX: &str = "ENVHOLSTER_";
pub const REVERSE_DNS_PREFIX: &str = "com.envholster";

/// G3 placeholder = `__envholster_<name>__`.
pub const PLACEHOLDER_PREFIX: &str = "__envholster_";
pub const PLACEHOLDER_SUFFIX: &str = "__";

pub const PLUGIN_ALLOWLIST: &[&str] = &["yubikey", "se"];

pub const SCRYPT_LOG_N_MIN: u8 = 20;
pub const SCRYPT_LOG_N_MAX: u8 = 22;

pub const BASE_ENV: &str = "base";

pub const FILE_MODE_SECRET: u32 = 0o600;
pub const DIR_MODE_SECRET: u32 = 0o700;

// §4.5 re-freeze note: const-assert the discriminant table against the §4.3
// enums so they cannot drift.
const _: () = {
    use crate::record::{Guarantee, SecretMode};

    assert!(MODE_GENERIC == SecretMode::Generic as u8);
    assert!(MODE_ENV_VAR == SecretMode::EnvVar as u8);
    assert!(MODE_SSH_KEY == SecretMode::SshKey as u8);
    assert!(MODE_API_KEY == SecretMode::ApiKey as u8);

    assert!(GUARANTEE_UNASSIGNED == Guarantee::Unassigned as u8);
    assert!(GUARANTEE_G_MIN == Guarantee::BrokeredResign as u8);
    assert!(Guarantee::BrokeredDerived as u8 == 2);
    assert!(Guarantee::BrokeredHeader as u8 == 3);
    assert!(Guarantee::BrokeredSign as u8 == 4);
    assert!(GUARANTEE_G_MAX == Guarantee::InjectedEnv as u8);

    assert!(VAULT_MAGIC.len() == 12);
    assert!(SCHEMA == crate::vault::Vault::SCHEMA);
};
