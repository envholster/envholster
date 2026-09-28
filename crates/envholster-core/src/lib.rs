//! envholster-core — schema-1 vault engine (frozen API: plan/04-contracts §4.3).
//!
//! Envelope bytes: plan/02-envelope. Memory rules: plan/03-memory — body bytes
//! touch only locked buffers; HB1 and the header are hand-written canonical
//! encodings; serde+toml serve the plaintext manifest only, NEVER an encrypted
//! path (c6/c20).

#![forbid(unsafe_code)]

pub mod constants;
pub mod dotenv;
pub mod expand;
pub mod manifest;
pub mod providers;

mod commit;
mod encoding;
mod envelope;
mod error;
mod hb1;
mod record;
mod recovery;
mod types;
mod ui;
mod vault;
mod wrap;

#[cfg(test)]
mod golden_gen;

pub use dotenv::{
    classify, is_valid_var_name, parse_dotenv, readers_agree, readers_disagree_reason,
    write_dotenv_line, Classification, DotenvEntry, Suggestion,
};
pub use encoding::{hmac_sha256_hex_lower, sha256_hex_lower};
pub use error::CoreError;
pub use manifest::{
    CheckFinding, EnvPassthrough, ExecSection, LocalOverride, Manifest, ManifestError, SecretDecl,
    SecretScope, SecretSource, VarValue,
};
pub use providers::{is_admin_key, recognize, BrokeredProvider};
pub use record::{CellId, CellStatus, Guarantee, SecretMeta, SecretMode, SecretRecord, VaultUuid};
pub use types::{
    parse_identities, Enrollment, EnvName, EnvSelector, Identity, PluginName, RecipientClass,
    RecipientEntry, RecipientId, RecipientKind, Tier,
};
pub use ui::{AgeCallbackAdapter, UnlockUi, WrapContext};
pub use vault::Vault;
