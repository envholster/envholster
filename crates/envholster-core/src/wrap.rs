//! DEK wrapping at the age boundary (plan/02-envelope §6, plan/04 §4.1).
//!
//! Each DEK is wrapped PER RECIPIENT as a separate single-recipient age
//! operation — one small age blob per (cell, recipient). Separate headers
//! mean scrypt, X25519, and plugin recipients never share an age header,
//! sidestepping `MixedRecipientAndPassphrase`.
//!
//! scrypt posture (c21): encrypt-side work factor clamped to
//! `log_n ∈ [SCRYPT_LOG_N_MIN, SCRYPT_LOG_N_MAX]` and recorded in the header;
//! decrypt-side ALWAYS runs under `set_max_work_factor(SCRYPT_LOG_N_MAX)` —
//! the fixed cap, not the attacker-writable header field, is the operative
//! anti-tamper/anti-DoS control. `WrongPassphrase` never aborts the unwrap
//! loop.
//!
//! Memory (plan/03 window 3/4): the DEK is read via age's `Decryptor` reader
//! with `read_exact` into a pre-sized `Zeroizing<[u8; 32]>` — never the
//! convenience-fn `Vec`. age's scrypt/STREAM internals and the by-value
//! `SecretString` passphrase are the documented irreducible residual.

use std::io::Read;
use std::iter;

use zeroize::Zeroizing;

use crate::constants::{DEK_LEN, SCRYPT_LOG_N_MAX, SCRYPT_LOG_N_MIN};
use crate::error::CoreError;
use crate::record::CellId;
use crate::types::{Identity, RecipientEntry, RecipientKind};
use crate::ui::{AgeCallbackAdapter, WrapContext};

/// Locked-adjacent DEK staging type at the age boundary (plan/04 §4.1).
/// TODO(stage B): vault-resident DEKs live in `envholster_mem::SecretBytes`;
/// this `Zeroizing` array is only the pinned staging form for age I/O.
pub(crate) type DekBytes = Zeroizing<[u8; DEK_LEN]>;

/// Outcome of trying ONE (wrap blob, identity) pair — the c21 loop alphabet.
pub(crate) enum UnwrapAttempt {
    Unwrapped(DekBytes),
    /// `NoMatchingKeys`: this identity cannot address this blob; try the next.
    NoMatch,
    /// `DecryptionFailed` on a SCRYPT blob — safe to interpret as a wrong
    /// passphrase (or tampered blob) because every blob is single-recipient.
    /// Never aborts the loop; surfaced as a re-prompt hint at the end.
    WrongPassphrase,
}

/// Wraps a DEK to one recipient: one single-recipient age encryption.
///
/// For scrypt recipients the passphrase is requested through `ctx` — wrap-time
/// secrets are never stored on a `RecipientEntry` (plan/04 §4.3). Plugin wraps
/// drive the age plugin binary with `ctx` as the callback surface (c4).
pub(crate) fn wrap_dek(
    dek: &DekBytes,
    entry: &RecipientEntry,
    ctx: &WrapContext,
) -> Result<Vec<u8>, CoreError> {
    let missing_encoding = || CoreError::HeaderParse {
        reason: format!(
            "recipient {} has no stored encoding to wrap to",
            entry.id.as_str()
        ),
    };
    match &entry.kind {
        RecipientKind::X25519 => {
            let encoded = entry.encoded.as_deref().ok_or_else(missing_encoding)?;
            let recipient = encoded
                .parse::<age::x25519::Recipient>()
                .map_err(|reason| CoreError::InvalidName {
                    name: encoded.to_owned(),
                    reason: reason.to_owned(),
                })?;
            Ok(age::encrypt(&recipient, &dek[..])?)
        }
        RecipientKind::Scrypt { log_n } => {
            let passphrase = ctx
                .ui
                .secret(&format!(
                    "Passphrase for scrypt recipient {} ({})",
                    entry.id.as_str(),
                    entry.label
                ))
                .ok_or_else(|| {
                    CoreError::Io(std::io::Error::other(
                        "scrypt passphrase prompt declined; cannot wrap DEK",
                    ))
                })?;
            let mut recipient = age::scrypt::Recipient::new(passphrase);
            // Defense in depth: the entry is clamped at enrollment, but the
            // encrypt clamp is re-applied here so no in-memory tampering can
            // produce an out-of-range work factor (c21).
            recipient.set_work_factor((*log_n).clamp(SCRYPT_LOG_N_MIN, SCRYPT_LOG_N_MAX));
            Ok(age::encrypt(&recipient, &dek[..])?)
        }
        RecipientKind::Plugin { name } => {
            let encoded = entry.encoded.as_deref().ok_or_else(missing_encoding)?;
            let recipient = encoded
                .parse::<age::plugin::Recipient>()
                .map_err(|reason| CoreError::InvalidName {
                    name: encoded.to_owned(),
                    reason: reason.to_owned(),
                })?;
            let plugin_recipient = age::plugin::RecipientPluginV1::new(
                name.as_str(),
                &[recipient],
                &[],
                AgeCallbackAdapter(ctx.ui.clone()),
            )?;
            Ok(age::encrypt(&plugin_recipient, &dek[..])?)
        }
    }
}

/// Classifies a failed age decryption per the frozen c21 rule. Factored out
/// so the classification itself is unit-testable without running scrypt.
pub(crate) fn classify_decrypt_failure(
    error: age::DecryptError,
    blob_is_scrypt: bool,
) -> Result<UnwrapAttempt, CoreError> {
    match error {
        age::DecryptError::NoMatchingKeys => Ok(UnwrapAttempt::NoMatch),
        age::DecryptError::DecryptionFailed if blob_is_scrypt => Ok(UnwrapAttempt::WrongPassphrase),
        age::DecryptError::ExcessiveWork { required, .. } => Err(CoreError::ExcessiveWork {
            required,
            max: SCRYPT_LOG_N_MAX,
        }),
        other => Err(CoreError::AgeDecrypt(other)),
    }
}

/// Tries to unwrap one wrap blob with one identity.
///
/// `blob_is_scrypt` comes from the header's recipient `kind`, NOT from the
/// blob itself — but interpretation stays safe either way because every blob
/// is single-recipient (plan/02 §6).
pub(crate) fn try_unwrap_dek(
    blob: &[u8],
    blob_is_scrypt: bool,
    identity: &Identity,
    ctx: &WrapContext,
) -> Result<UnwrapAttempt, CoreError> {
    let decryptor = match age::Decryptor::new_buffered(blob) {
        Ok(decryptor) => decryptor,
        Err(error) => return classify_decrypt_failure(error, blob_is_scrypt),
    };

    let result = match identity {
        Identity::X25519(identity) => decryptor.decrypt(iter::once(identity as &dyn age::Identity)),
        Identity::Scrypt(passphrase) => {
            if !decryptor.is_scrypt() {
                // A passphrase can never address a non-scrypt blob; skip the
                // scrypt::Identity construction entirely.
                return Ok(UnwrapAttempt::NoMatch);
            }
            let mut identity = age::scrypt::Identity::new(passphrase.clone());
            // The fixed cap — never the header's log_n — bounds decrypt work
            // (c21). A hostile work factor surfaces as ExcessiveWork.
            identity.set_max_work_factor(SCRYPT_LOG_N_MAX);
            decryptor.decrypt(iter::once(&identity as &dyn age::Identity))
        }
        Identity::Plugin { name, encoded } => {
            let plugin_identity = encoded.parse::<age::plugin::Identity>().map_err(|reason| {
                CoreError::InvalidName {
                    name: name.as_str().to_owned(),
                    reason: reason.to_owned(),
                }
            })?;
            let identity = age::plugin::IdentityPluginV1::new(
                name.as_str(),
                &[plugin_identity],
                AgeCallbackAdapter(ctx.ui.clone()),
            )
            .map_err(CoreError::AgeDecrypt)?;
            decryptor.decrypt(iter::once(&identity as &dyn age::Identity))
        }
    };

    let mut reader = match result {
        Ok(reader) => reader,
        Err(error) => return classify_decrypt_failure(error, blob_is_scrypt),
    };

    // Pre-sized Zeroizing staging (plan/03 window 3); never a Vec.
    let mut dek: DekBytes = Zeroizing::new([0u8; DEK_LEN]);
    reader.read_exact(&mut dek[..]).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            CoreError::HeaderParse {
                reason: "wrap blob payload is shorter than a DEK".to_owned(),
            }
        } else {
            CoreError::Io(error)
        }
    })?;
    let mut probe = [0u8; 1];
    match reader.read(&mut probe) {
        Ok(0) => Ok(UnwrapAttempt::Unwrapped(dek)),
        _ => Err(CoreError::HeaderParse {
            reason: "wrap blob payload is not exactly one DEK".to_owned(),
        }),
    }
}

/// One wrap of a cell, as needed by the unwrap loop; assembled by the vault
/// from the header's cell wraps joined to recipient kinds.
pub(crate) struct CellWrap<'a> {
    pub is_scrypt: bool,
    pub blob: &'a [u8],
}

/// The frozen per-cell unwrap loop (c21): every (wrap, identity) pair is
/// tried; `NoMatch` and `WrongPassphrase` continue; the first success wins;
/// exhaustion yields `NoMatchingIdentity` carrying the re-prompt hint.
/// Hard failures (tampered work factor, malformed blobs, plugin errors)
/// abort immediately.
pub(crate) fn unwrap_cell_dek(
    cell: &CellId,
    wraps: &[CellWrap<'_>],
    identities: &[Identity],
    ctx: &WrapContext,
) -> Result<DekBytes, CoreError> {
    let mut saw_wrong_passphrase = false;
    for wrap in wraps {
        for identity in identities {
            match try_unwrap_dek(wrap.blob, wrap.is_scrypt, identity, ctx)? {
                UnwrapAttempt::Unwrapped(dek) => return Ok(dek),
                UnwrapAttempt::NoMatch => {}
                UnwrapAttempt::WrongPassphrase => saw_wrong_passphrase = true,
            }
        }
    }
    Err(CoreError::NoMatchingIdentity {
        env: cell.env.as_str().to_owned(),
        tier: cell.tier.as_u8(),
        saw_wrong_passphrase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Enrollment, EnvName, EnvSelector, RecipientClass, Tier};
    use crate::ui::UnlockUi;
    use secrecy::SecretString;
    use std::sync::Arc;

    fn all_enrollment() -> Enrollment {
        Enrollment(EnvSelector::All {
            max_tier: Tier::Critical,
        })
    }

    fn fresh_dek() -> DekBytes {
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        getrandom::fill(&mut dek[..]).unwrap();
        dek
    }

    fn cell() -> CellId {
        CellId {
            env: EnvName::parse("prod").unwrap(),
            tier: Tier::Critical,
        }
    }

    /// Test-only UI answering every secret prompt with a fixed passphrase.
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

    #[test]
    fn x25519_wrap_unwrap_round_trip() {
        let identity = age::x25519::Identity::generate();
        let entry = RecipientEntry::from_encoded(
            &identity.to_public().to_string(),
            RecipientClass::Software,
            "laptop".to_owned(),
            all_enrollment(),
        )
        .unwrap();
        let ctx = WrapContext::silent();
        let dek = fresh_dek();
        let blob = wrap_dek(&dek, &entry, &ctx).unwrap();

        match try_unwrap_dek(&blob, false, &Identity::X25519(identity), &ctx).unwrap() {
            UnwrapAttempt::Unwrapped(out) => assert_eq!(&out[..], &dek[..]),
            _ => panic!("expected successful unwrap"),
        }

        // A different identity is NoMatch — never a hard error (c21).
        let stranger = age::x25519::Identity::generate();
        assert!(matches!(
            try_unwrap_dek(&blob, false, &Identity::X25519(stranger), &ctx).unwrap(),
            UnwrapAttempt::NoMatch
        ));
    }

    #[test]
    fn consecutive_wraps_of_same_dek_differ() {
        // age draws a fresh file key + nonce per encryption; two wraps of the
        // same DEK to the same recipient must not be byte-identical.
        let identity = age::x25519::Identity::generate();
        let entry = RecipientEntry::from_encoded(
            &identity.to_public().to_string(),
            RecipientClass::Software,
            "laptop".to_owned(),
            all_enrollment(),
        )
        .unwrap();
        let ctx = WrapContext::silent();
        let dek = fresh_dek();
        assert_ne!(
            wrap_dek(&dek, &entry, &ctx).unwrap(),
            wrap_dek(&dek, &entry, &ctx).unwrap()
        );
    }

    #[test]
    fn unwrap_loop_tries_all_identities_and_reports_exhaustion() {
        let right = age::x25519::Identity::generate();
        let wrong = age::x25519::Identity::generate();
        let entry = RecipientEntry::from_encoded(
            &right.to_public().to_string(),
            RecipientClass::Software,
            "laptop".to_owned(),
            all_enrollment(),
        )
        .unwrap();
        let ctx = WrapContext::silent();
        let dek = fresh_dek();
        let blob = wrap_dek(&dek, &entry, &ctx).unwrap();
        let wraps = [CellWrap {
            is_scrypt: false,
            blob: &blob,
        }];

        // Wrong identity first: the loop continues to the matching one.
        let identities = [Identity::X25519(wrong), Identity::X25519(right)];
        let out = unwrap_cell_dek(&cell(), &wraps, &identities, &ctx).unwrap();
        assert_eq!(&out[..], &dek[..]);

        // Only wrong identities: NoMatchingIdentity without a passphrase hint.
        let only_wrong = [Identity::X25519(age::x25519::Identity::generate())];
        assert!(matches!(
            unwrap_cell_dek(&cell(), &wraps, &only_wrong, &ctx),
            Err(CoreError::NoMatchingIdentity {
                saw_wrong_passphrase: false,
                ..
            })
        ));
    }

    #[test]
    fn scrypt_identity_skips_non_scrypt_blobs() {
        let identity = age::x25519::Identity::generate();
        let entry = RecipientEntry::from_encoded(
            &identity.to_public().to_string(),
            RecipientClass::Software,
            "laptop".to_owned(),
            all_enrollment(),
        )
        .unwrap();
        let ctx = WrapContext::silent();
        let blob = wrap_dek(&fresh_dek(), &entry, &ctx).unwrap();
        assert!(matches!(
            try_unwrap_dek(
                &blob,
                false,
                &Identity::Scrypt(SecretString::from("whatever".to_owned())),
                &ctx
            )
            .unwrap(),
            UnwrapAttempt::NoMatch
        ));
    }

    #[test]
    fn decrypt_failure_classification_follows_c21() {
        // DecryptionFailed on a scrypt blob = wrong passphrase; loop continues.
        assert!(matches!(
            classify_decrypt_failure(age::DecryptError::DecryptionFailed, true),
            Ok(UnwrapAttempt::WrongPassphrase)
        ));
        // DecryptionFailed elsewhere is a hard error, classified last.
        assert!(matches!(
            classify_decrypt_failure(age::DecryptError::DecryptionFailed, false),
            Err(CoreError::AgeDecrypt(age::DecryptError::DecryptionFailed))
        ));
        // NoMatchingKeys always means "try the next identity".
        assert!(matches!(
            classify_decrypt_failure(age::DecryptError::NoMatchingKeys, false),
            Ok(UnwrapAttempt::NoMatch)
        ));
        // A hostile work factor surfaces as ExcessiveWork against the FIXED
        // cap — tampered or unsupported, never attempted.
        assert!(matches!(
            classify_decrypt_failure(
                age::DecryptError::ExcessiveWork {
                    required: 30,
                    target: 18
                },
                true
            ),
            Err(CoreError::ExcessiveWork {
                required: 30,
                max: SCRYPT_LOG_N_MAX
            })
        ));
    }

    #[test]
    fn wrap_blob_with_wrong_payload_length_is_rejected() {
        let identity = age::x25519::Identity::generate();
        let ctx = WrapContext::silent();
        // A valid age blob whose payload is NOT a 32-byte DEK.
        let blob = age::encrypt(&identity.to_public(), b"short").unwrap();
        assert!(matches!(
            try_unwrap_dek(&blob, false, &Identity::X25519(identity), &ctx),
            Err(CoreError::HeaderParse { .. })
        ));

        let identity2 = age::x25519::Identity::generate();
        let blob = age::encrypt(&identity2.to_public(), &[0u8; DEK_LEN + 1]).unwrap();
        assert!(matches!(
            try_unwrap_dek(&blob, false, &Identity::X25519(identity2), &ctx),
            Err(CoreError::HeaderParse { .. })
        ));
    }

    #[test]
    fn scrypt_prompt_decline_fails_wrap_closed() {
        let entry = RecipientEntry::scrypt("team".to_owned(), all_enrollment(), 20).unwrap();
        // WrapContext::silent() answers every secret prompt with None.
        assert!(matches!(
            wrap_dek(&fresh_dek(), &entry, &WrapContext::silent()),
            Err(CoreError::Io(_))
        ));
    }

    /// Full scrypt round-trip incl. the wrong-passphrase-continues-loop rule.
    ///
    /// #[ignore]: plan/02 §6 clamps the encrypt work factor to log_n ≥ 20
    /// (no lower value is permitted, so the test cannot be made cheap), and
    /// 2^20 scrypt under the unoptimized test profile takes tens of seconds
    /// per operation. Run explicitly with:
    ///   cargo test -p envholster-core -- --ignored
    #[test]
    #[ignore = "log_n=20 is the plan/02 floor; scrypt at 2^20 is expensive in debug builds"]
    fn scrypt_wrap_unwrap_round_trip_and_wrong_passphrase() {
        let entry = RecipientEntry::scrypt("team".to_owned(), all_enrollment(), 20).unwrap();
        let ctx = WrapContext::new(Arc::new(FixedPassphraseUi("correct horse")));
        let dek = fresh_dek();
        let blob = wrap_dek(&dek, &entry, &ctx).unwrap();
        let wraps = [CellWrap {
            is_scrypt: true,
            blob: &blob,
        }];

        // Correct passphrase unwraps.
        let good = [Identity::Scrypt(SecretString::from(
            "correct horse".to_owned(),
        ))];
        let out = unwrap_cell_dek(&cell(), &wraps, &good, &ctx).unwrap();
        assert_eq!(&out[..], &dek[..]);

        // Wrong passphrase: the loop continues past it to a later identity
        // (c21) — here exhaustion, with the re-prompt hint set.
        let bad = [Identity::Scrypt(SecretString::from("wrong".to_owned()))];
        assert!(matches!(
            unwrap_cell_dek(&cell(), &wraps, &bad, &ctx),
            Err(CoreError::NoMatchingIdentity {
                saw_wrong_passphrase: true,
                ..
            })
        ));

        // Wrong-then-right within one loop still succeeds.
        let mixed = [
            Identity::Scrypt(SecretString::from("wrong".to_owned())),
            Identity::Scrypt(SecretString::from("correct horse".to_owned())),
        ];
        let out = unwrap_cell_dek(&cell(), &wraps, &mixed, &ctx).unwrap();
        assert_eq!(&out[..], &dek[..]);
    }
}
