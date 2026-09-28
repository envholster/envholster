//! Frozen error taxonomy (plan/04-contracts §4.3).
//!
//! Display strings never contain secret material — names, envs, and tiers
//! only. Frozen decrypt-loop rule (c21): `NoMatchingKeys` ⇒ try next identity;
//! `DecryptionFailed` on a scrypt blob ⇒ wrong passphrase or tampered blob ⇒
//! set `saw_wrong_passphrase`, continue the loop, surface a re-prompt hint in
//! the final `NoMatchingIdentity`. A wrong passphrase never aborts the loop.

use crate::types::RecipientClass;
use envholster_mem::MemError;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Mem(#[from] MemError),

    #[error(transparent)]
    Entropy(#[from] getrandom::Error),

    #[error(transparent)]
    AgeEncrypt(#[from] age::EncryptError),

    /// NOT `#[from]`: the unwrap loop classifies first (c21).
    #[error("age decryption failed: {0}")]
    AgeDecrypt(age::DecryptError),

    /// ONE variant for commitment failure AND tag failure (c2).
    #[error("authenticated decryption failed for cell {env}:{tier}")]
    AeadFailed { env: String, tier: u8 },

    #[error("no supplied identity can unwrap cell {env}:{tier} (wrong passphrase seen: {saw_wrong_passphrase} — if true, re-enter it and retry)")]
    NoMatchingIdentity {
        env: String,
        tier: u8,
        saw_wrong_passphrase: bool,
    },

    #[error("wrong passphrase")]
    WrongPassphrase,

    #[error("scrypt work factor {required} exceeds the fixed cap {max}; refusing to decrypt")]
    ExcessiveWork { required: u8, max: u8 },

    #[error("vault header parse failed: {reason}")]
    HeaderParse { reason: String },

    #[error("unsupported vault schema {found} (this build supports {supported}); run a newer envholster")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("vault from a newer version: unknown recipient kind {kind:?}")]
    UnknownRecipientKind { kind: String },

    #[error("age plugin {0:?} is not on the allowlist")]
    PluginNotAllowed(String),

    #[error("secret {0:?} not found")]
    SecretNotFound(String),

    #[error("recipient {0:?} not found")]
    RecipientNotFound(String),

    /// Wrap matrix G-A: NO override exists.
    #[error(
        "recipient {recipient:?} (class {class:?}) may not be wrapped to cell {env}:{tier} (wrap matrix G-A; no override)"
    )]
    ForbiddenWrap {
        recipient: String,
        class: RecipientClass,
        env: String,
        tier: u8,
    },

    #[error("cell {env}:{tier} is locked")]
    CellLocked { env: String, tier: u8 },

    /// D6: save fails closed without the recovery blob.
    #[error("recovery blob write failed; save aborted: {reason}")]
    RecoveryLockstep { reason: String },

    #[error("exactly one Recovery-class recipient is required, found {found}")]
    RecoveryRecipientCount { found: usize },

    #[error("invalid name {name:?}: {reason}")]
    InvalidName { name: String, reason: String },
}

impl CoreError {
    /// Is this an age PLUGIN-reported decrypt failure
    /// (`AgeDecrypt(DecryptError::Plugin(_))`)?
    ///
    /// This is what a human-refused hardware ceremony looks like from the
    /// unwrap loop: age-plugin-yubikey reports a wrong/cancelled PIN and
    /// age-plugin-se reports a dismissed LAContext sheet as PLUGIN errors, not
    /// as `NoMatchingKeys` — so they abort the c21 loop as hard failures
    /// (`classify_decrypt_failure` is FROZEN and must keep doing that: the
    /// non-interactive paths want a broken plugin to fail loudly).
    ///
    /// The daemon's INTERACTIVE unlock path is the one caller entitled to a
    /// softer policy — there a refusal is an ordinary human outcome, not a
    /// protocol error — and it needs this predicate because it deliberately
    /// does not depend on the `age` crate and so cannot name the variant in a
    /// pattern. This is an INSPECTOR only: no plugin error text is exposed,
    /// so nothing here can leak plugin stderr into a caller's message.
    pub fn is_plugin_decrypt_error(&self) -> bool {
        matches!(self, CoreError::AgeDecrypt(age::DecryptError::Plugin(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The predicate matches EXACTLY the plugin-reported decrypt failure — the
    /// shape a PIN-refusal / LAContext-dismiss surfaces as (spike 1) — and
    /// nothing else, so the daemon's per-cell tolerance cannot widen into
    /// swallowing genuine decrypt corruption.
    #[test]
    fn plugin_decrypt_predicate_matches_only_the_plugin_variant() {
        assert!(
            CoreError::AgeDecrypt(age::DecryptError::Plugin(Vec::new())).is_plugin_decrypt_error()
        );
        for other in [
            CoreError::AgeDecrypt(age::DecryptError::DecryptionFailed),
            CoreError::AgeDecrypt(age::DecryptError::NoMatchingKeys),
            CoreError::AgeDecrypt(age::DecryptError::InvalidHeader),
            CoreError::WrongPassphrase,
            CoreError::AeadFailed {
                env: "base".to_owned(),
                tier: 2,
            },
        ] {
            assert!(!other.is_plugin_decrypt_error(), "over-matched: {other:?}");
        }
    }
}
