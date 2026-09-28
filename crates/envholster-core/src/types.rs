//! Newtypes, recipients, identities (frozen shapes: plan/04-contracts §4.3).

use std::collections::BTreeMap;

use secrecy::SecretString;
use sha2::{Digest, Sha256};

use crate::constants::{PLUGIN_ALLOWLIST, SCRYPT_LOG_N_MAX, SCRYPT_LOG_N_MIN};
use crate::error::CoreError;

/// Domain-separation prefix for keyed recipient-id derivation
/// (plan/02-envelope §1). Not part of the frozen constants table (§4.5), so it
/// stays crate-private here.
pub(crate) const RECIPIENT_ID_CONTEXT: &[u8] = b"envholster-v1-rcpt:";

/// Recipient-id length in lowercase hex chars (= 8 bytes; plan/02-envelope §1).
pub(crate) const RECIPIENT_ID_HEX_LEN: usize = 16;

/// Header `label` field limit in bytes (plan/02-envelope §3).
pub(crate) const LABEL_MAX_BYTES: usize = 64;

/// Environment name: `[a-z0-9][a-z0-9_-]{0,31}`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvName(String);

impl EnvName {
    /// Validates against `[a-z0-9][a-z0-9_-]{0,31}`; `InvalidName` otherwise.
    ///
    /// `:` and `*` are excluded by construction, so the plan/02 §4 AAD suffix
    /// and the §3 enroll wildcard are both unambiguous.
    pub fn parse(name: &str) -> Result<Self, CoreError> {
        let bytes = name.as_bytes();
        let charset_ok = !bytes.is_empty()
            && bytes.len() <= 32
            && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
            && bytes[1..]
                .iter()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
        if charset_ok {
            Ok(EnvName(name.to_owned()))
        } else {
            Err(CoreError::InvalidName {
                name: name.to_owned(),
                reason: "environment names must match [a-z0-9][a-z0-9_-]{0,31}".to_owned(),
            })
        }
    }

    /// Construct an `EnvName` holding a SECRET name (not an environment name).
    /// Some callers type secret names as `EnvName`, but secret
    /// names use the broader vault charset `[A-Za-z0-9_.-]{1,128}` (uppercase
    /// env-var names like `ANTHROPIC_API_KEY`), NOT the lowercase environment-name
    /// charset [`Self::parse`] enforces. This additive constructor validates that
    /// broader charset — it does NOT change env-name parsing (`:`/`*`/whitespace
    /// remain excluded, so AAD/wildcard framing stays unambiguous).
    pub fn secret_name(name: &str) -> Result<Self, CoreError> {
        let bytes = name.as_bytes();
        let ok = !bytes.is_empty()
            && bytes.len() <= 128
            && bytes
                .iter()
                .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'));
        if ok {
            Ok(EnvName(name.to_owned()))
        } else {
            Err(CoreError::InvalidName {
                name: name.to_owned(),
                reason: "secret names must match [A-Za-z0-9_.-]{1,128}".to_owned(),
            })
        }
    }

    /// The default environment, `constants::BASE_ENV`.
    pub fn base() -> Self {
        EnvName(crate::constants::BASE_ENV.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Secret tier (D1). Cell topology is one DEK per (env × tier) cell.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Ambient = 1,
    Sensitive = 2,
    Critical = 3,
}

impl Tier {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Tier::Ambient),
            2 => Some(Tier::Sensitive),
            3 => Some(Tier::Critical),
            _ => None,
        }
    }
}

/// Age plugin name: charset-validated AND allowlisted against
/// `constants::PLUGIN_ALLOWLIST` = {yubikey, se} (RUSTSEC-2024-0433).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginName(String);

impl PluginName {
    /// Charset `[a-z0-9-]{1,32}` (`InvalidName`), then the allowlist
    /// (`PluginNotAllowed`). Both checks run at parse time — a plugin name
    /// never reaches process spawning unvalidated.
    pub fn parse(name: &str) -> Result<Self, CoreError> {
        let bytes = name.as_bytes();
        let charset_ok = !bytes.is_empty()
            && bytes.len() <= 32
            && bytes
                .iter()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'));
        if !charset_ok {
            return Err(CoreError::InvalidName {
                name: name.to_owned(),
                reason: "plugin names must match [a-z0-9-]{1,32}".to_owned(),
            });
        }
        if !PLUGIN_ALLOWLIST.contains(&name) {
            return Err(CoreError::PluginNotAllowed(name.to_owned()));
        }
        Ok(PluginName(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable header id of a recipient; derivation: plan/02-envelope §1.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipientId(String);

impl RecipientId {
    /// Charset-validates a caller-supplied id (e.g. `recipient rm <id>`):
    /// exactly 16 lowercase hex chars.
    pub fn parse(id: &str) -> Result<Self, CoreError> {
        let bytes = id.as_bytes();
        let ok = bytes.len() == RECIPIENT_ID_HEX_LEN
            && bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if ok {
            Ok(RecipientId(id.to_owned()))
        } else {
            Err(CoreError::InvalidName {
                name: id.to_owned(),
                reason: "recipient ids are exactly 16 lowercase hex characters".to_owned(),
            })
        }
    }

    /// Keyed kinds (plan/02-envelope §1): first 8 bytes of
    /// SHA-256(`"envholster-v1-rcpt:"` ‖ full recipient encoding), lowercase hex.
    pub(crate) fn derive(encoded: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(RECIPIENT_ID_CONTEXT);
        hasher.update(encoded.as_bytes());
        let digest = hasher.finalize();
        RecipientId(crate::encoding::hex_encode(
            &digest[..RECIPIENT_ID_HEX_LEN / 2],
        ))
    }

    /// Scrypt kinds (plan/02-envelope §1): 8 `getrandom` bytes at enrollment.
    pub(crate) fn random() -> Result<Self, CoreError> {
        let mut bytes = [0u8; RECIPIENT_ID_HEX_LEN / 2];
        getrandom::fill(&mut bytes)?;
        Ok(RecipientId(crate::encoding::hex_encode(&bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Recipient class — load-bearing: sets the wrap-matrix floor (G-A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecipientClass {
    Hardware,
    Software,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientKind {
    X25519,
    Scrypt { log_n: u8 },
    Plugin { name: PluginName },
}

/// Exact in-memory form of the plan/02-envelope §3 `enroll` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvSelector {
    /// `*:<max_tier>` — every environment, present and future.
    All { max_tier: Tier },
    /// `<env>:<max_tier>` pairs, BTree-sorted; per-env max_tier may differ.
    Named(BTreeMap<EnvName, Tier>),
}

/// Round-trips the header `enroll` field byte-exact in both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment(pub EnvSelector);

impl Enrollment {
    /// Canonical header-field encoding (plan/02-envelope §3): the wildcard
    /// stands alone; named entries sorted ascending by env (BTreeMap order),
    /// comma-joined, no spaces.
    pub(crate) fn to_header_field(&self) -> String {
        match &self.0 {
            EnvSelector::All { max_tier } => format!("*:{}", max_tier.as_u8()),
            EnvSelector::Named(map) => {
                let mut out = String::new();
                for (env, tier) in map {
                    if !out.is_empty() {
                        out.push(',');
                    }
                    out.push_str(env.as_str());
                    out.push(':');
                    out.push((b'0' + tier.as_u8()) as char);
                }
                out
            }
        }
    }

    /// Strict inverse of [`Self::to_header_field`]. Mixing `*` with named
    /// entries, listing `*` more than once, unsorted or duplicate envs, and
    /// out-of-range tiers are all `HeaderParse` (plan/02-envelope §3).
    pub(crate) fn parse_header_field(field: &str) -> Result<Self, CoreError> {
        let err = |reason: &str| CoreError::HeaderParse {
            reason: format!("enroll field: {reason}"),
        };
        if field.is_empty() {
            return Err(err("empty"));
        }
        fn parse_pair(pair: &str) -> Result<(&str, Tier), CoreError> {
            let err = |reason: &str| CoreError::HeaderParse {
                reason: format!("enroll field: {reason}"),
            };
            let (env, tier) = pair
                .split_once(':')
                .ok_or_else(|| err("entries are <env>:<max_tier>"))?;
            let tier_byte = tier.as_bytes();
            if tier_byte.len() != 1 {
                return Err(err("max_tier is a single digit 1-3"));
            }
            let tier = Tier::try_from_u8(tier_byte[0].wrapping_sub(b'0'))
                .ok_or_else(|| err("max_tier is a single digit 1-3"))?;
            Ok((env, tier))
        }
        if let Some(rest) = field.strip_prefix("*:") {
            // Canonical wildcard: `*:<max_tier>` standing alone.
            let rest = rest.as_bytes();
            if rest.len() != 1 {
                return Err(err("the wildcard stands alone as *:<max_tier>"));
            }
            let tier = Tier::try_from_u8(rest[0].wrapping_sub(b'0'))
                .ok_or_else(|| err("max_tier is a single digit 1-3"))?;
            return Ok(Enrollment(EnvSelector::All { max_tier: tier }));
        }
        let mut map = BTreeMap::new();
        let mut prev: Option<String> = None;
        for pair in field.split(',') {
            let (env_str, tier) = parse_pair(pair)?;
            if env_str == "*" {
                return Err(err("the wildcard stands alone"));
            }
            let env = EnvName::parse(env_str).map_err(|_| err("invalid environment name"))?;
            if let Some(prev) = &prev {
                if env.as_str() <= prev.as_str() {
                    return Err(err(
                        "entries must be sorted ascending by env, no duplicates",
                    ));
                }
            }
            prev = Some(env.as_str().to_owned());
            map.insert(env, tier);
        }
        Ok(Enrollment(EnvSelector::Named(map)))
    }
}

/// Header `label` rules (plan/02-envelope §3): UTF-8, no control characters,
/// ≤ 64 bytes. Leading/trailing ASCII whitespace is additionally rejected —
/// it cannot survive the canonical `key = value` line form.
pub(crate) fn validate_label(label: &str) -> Result<(), CoreError> {
    let invalid = |reason: &str| CoreError::InvalidName {
        name: label.to_owned(),
        reason: reason.to_owned(),
    };
    if label.len() > LABEL_MAX_BYTES {
        return Err(invalid("labels are at most 64 bytes"));
    }
    if label.chars().any(|c| c.is_control()) {
        return Err(invalid("labels must not contain control characters"));
    }
    if label.starts_with([' ', '\t']) || label.ends_with([' ', '\t']) {
        return Err(invalid(
            "labels must not start or end with whitespace (canonical header form)",
        ));
    }
    Ok(())
}

/// Class/kind consistency (plan/02-envelope §1): `hardware` = plugin
/// identities; `software` = X25519/scrypt/CI; `recovery` = one offline X25519.
pub(crate) fn check_class_kind(class: RecipientClass, kind: &RecipientKind) -> Result<(), String> {
    let ok = match kind {
        RecipientKind::Plugin { .. } => class == RecipientClass::Hardware,
        RecipientKind::X25519 => {
            class == RecipientClass::Software || class == RecipientClass::Recovery
        }
        RecipientKind::Scrypt { .. } => class == RecipientClass::Software,
    };
    if ok {
        Ok(())
    } else {
        Err(match kind {
            RecipientKind::Plugin { .. } => "plugin recipients must be hardware class".to_owned(),
            RecipientKind::X25519 => {
                "x25519 recipients must be software or recovery class".to_owned()
            }
            RecipientKind::Scrypt { .. } => "scrypt recipients must be software class".to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientEntry {
    pub id: RecipientId,
    pub class: RecipientClass,
    pub kind: RecipientKind,
    pub label: String,
    /// FULL encoded public key (c2/c4); `None` ONLY for Scrypt.
    pub encoded: Option<String>,
    pub enrollment: Enrollment,
}

impl RecipientEntry {
    /// Infers kind from the bech32 HRP; never yields Scrypt (no public
    /// encoding exists — scrypt entries are identified and removed by `id`).
    ///
    /// The encoding is re-serialized to its canonical lowercase form before
    /// the id is derived and stored, so byte-identical header round-trips do
    /// not depend on caller-supplied casing.
    pub fn from_encoded(
        encoded: &str,
        class: RecipientClass,
        label: String,
        enrollment: Enrollment,
    ) -> Result<Self, CoreError> {
        validate_label(&label)?;
        let invalid = |reason: String| CoreError::InvalidName {
            name: encoded.to_owned(),
            reason,
        };

        let (kind, canonical) = if let Ok(recipient) = encoded.parse::<age::x25519::Recipient>() {
            (RecipientKind::X25519, recipient.to_string())
        } else if let Ok(recipient) = encoded.parse::<age::plugin::Recipient>() {
            // Allowlist at parse (RUSTSEC-2024-0433): PluginNotAllowed
            // surfaces as itself, before any other validation.
            let name = PluginName::parse(recipient.plugin())?;
            (RecipientKind::Plugin { name }, recipient.to_string())
        } else {
            return Err(invalid("not a valid age recipient encoding".to_owned()));
        };

        check_class_kind(class, &kind).map_err(invalid)?;

        Ok(RecipientEntry {
            id: RecipientId::derive(&canonical),
            class,
            kind,
            label,
            encoded: Some(canonical),
            enrollment,
        })
    }

    /// Scrypt `log_n` clamped [SCRYPT_LOG_N_MIN, SCRYPT_LOG_N_MAX] at
    /// enrollment and recorded; decrypt always runs under the fixed cap (c21).
    pub fn scrypt(label: String, enrollment: Enrollment, log_n: u8) -> Result<Self, CoreError> {
        validate_label(&label)?;
        Ok(RecipientEntry {
            id: RecipientId::random()?,
            class: RecipientClass::Software,
            kind: RecipientKind::Scrypt {
                log_n: log_n.clamp(SCRYPT_LOG_N_MIN, SCRYPT_LOG_N_MAX),
            },
            label,
            encoded: None,
            enrollment,
        })
    }
}

/// Unlock identity. Wrap-time secrets (PIN, passphrase) are never stored on a
/// `RecipientEntry` — they flow through `WrapContext`.
pub enum Identity {
    X25519(age::x25519::Identity),
    Scrypt(SecretString),
    Plugin { name: PluginName, encoded: String },
}

/// Parse identity-file text into the identities the unwrap loop tries (c21).
/// Comment (`#`) and blank lines are skipped; `AGE-SECRET-KEY-1…` → an X25519
/// software identity; `AGE-PLUGIN-…` → an allowlisted plugin identity
/// (RUSTSEC-2024-0433). `source` names the origin for error messages only —
/// NEVER a secret value. Shared so the CLI and the daemon parse identity files
/// through one path (the daemon reads the `--identity` file named in a wire
/// `UnlockRequest`, spikes/P1-CONTRACT.md §7). A file with no identity line is
/// an error, mirroring the CLI's `parse_identity_text`.
pub fn parse_identities(text: &str, source: &str) -> Result<Vec<Identity>, CoreError> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_ascii_uppercase().starts_with("AGE-SECRET-KEY-1") {
            let identity =
                line.parse::<age::x25519::Identity>()
                    .map_err(|reason| CoreError::InvalidName {
                        name: source.to_owned(),
                        reason: format!("invalid X25519 identity: {reason}"),
                    })?;
            out.push(Identity::X25519(identity));
        } else if line.to_ascii_uppercase().starts_with("AGE-PLUGIN-") {
            let plugin =
                line.parse::<age::plugin::Identity>()
                    .map_err(|reason| CoreError::InvalidName {
                        name: source.to_owned(),
                        reason: format!("invalid plugin identity: {reason}"),
                    })?;
            let name = PluginName::parse(plugin.plugin())?;
            out.push(Identity::Plugin {
                name,
                encoded: line.to_owned(),
            });
        } else {
            return Err(CoreError::InvalidName {
                name: source.to_owned(),
                reason: "unrecognized identity line (expected AGE-SECRET-KEY-1… or AGE-PLUGIN-…)"
                    .to_owned(),
            });
        }
    }
    if out.is_empty() {
        return Err(CoreError::InvalidName {
            name: source.to_owned(),
            reason: "no identity found in identity source".to_owned(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_enrollment() -> Enrollment {
        Enrollment(EnvSelector::All {
            max_tier: Tier::Critical,
        })
    }

    #[test]
    fn env_name_charset() {
        assert!(EnvName::parse("prod").is_ok());
        assert!(EnvName::parse("0dev-a_b").is_ok());
        assert!(EnvName::parse(&"a".repeat(32)).is_ok());
        for bad in ["", "Prod", "-dev", "_dev", "dev:1", "a*", &"a".repeat(33)] {
            assert!(
                matches!(EnvName::parse(bad), Err(CoreError::InvalidName { .. })),
                "expected InvalidName for {bad:?}"
            );
        }
    }

    #[test]
    fn plugin_name_allowlist() {
        assert_eq!(PluginName::parse("yubikey").unwrap().as_str(), "yubikey");
        assert_eq!(PluginName::parse("se").unwrap().as_str(), "se");
        assert!(matches!(
            PluginName::parse("evil"),
            Err(CoreError::PluginNotAllowed(name)) if name == "evil"
        ));
        // Charset failures are InvalidName, before the allowlist.
        for bad in ["", "YubiKey", "yubi key", &"a".repeat(33)] {
            assert!(
                matches!(PluginName::parse(bad), Err(CoreError::InvalidName { .. })),
                "expected InvalidName for {bad:?}"
            );
        }
    }

    #[test]
    fn recipient_id_derivation_golden() {
        // SHA-256(b"envholster-v1-rcpt:age1example")[..8], computed
        // independently (Python hashlib).
        assert_eq!(
            RecipientId::derive("age1example").as_str(),
            "3b2e1bb3a01dad1b"
        );
    }

    #[test]
    fn recipient_id_parse_strictness() {
        assert!(RecipientId::parse("3b2e1bb3a01dad1b").is_ok());
        for bad in [
            "3b2e1bb3a01dad1",
            "3b2e1bb3a01dad1bb",
            "3B2E1BB3A01DAD1B",
            "3b2e1bb3a01dad1g",
        ] {
            assert!(
                RecipientId::parse(bad).is_err(),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn recipient_id_random_shape() {
        let id = RecipientId::random().unwrap();
        assert!(RecipientId::parse(id.as_str()).is_ok());
    }

    #[test]
    fn from_encoded_x25519() {
        let identity = age::x25519::Identity::generate();
        let encoded = identity.to_public().to_string();
        let entry = RecipientEntry::from_encoded(
            &encoded,
            RecipientClass::Software,
            "laptop".to_owned(),
            all_enrollment(),
        )
        .unwrap();
        assert_eq!(entry.kind, RecipientKind::X25519);
        assert_eq!(entry.encoded.as_deref(), Some(encoded.as_str()));
        assert_eq!(entry.id, RecipientId::derive(&encoded));

        // Recovery class is legal for x25519; hardware is not (plan/02 §1).
        assert!(RecipientEntry::from_encoded(
            &encoded,
            RecipientClass::Recovery,
            "paper".to_owned(),
            all_enrollment(),
        )
        .is_ok());
        assert!(matches!(
            RecipientEntry::from_encoded(
                &encoded,
                RecipientClass::Hardware,
                "nope".to_owned(),
                all_enrollment(),
            ),
            Err(CoreError::InvalidName { .. })
        ));
    }

    #[test]
    fn from_encoded_rejects_garbage_and_bad_labels() {
        assert!(matches!(
            RecipientEntry::from_encoded(
                "not-an-age-recipient",
                RecipientClass::Software,
                "x".to_owned(),
                all_enrollment(),
            ),
            Err(CoreError::InvalidName { .. })
        ));
        let encoded = age::x25519::Identity::generate().to_public().to_string();
        for bad_label in [
            "a".repeat(65),
            "tab\tin\nlabel".to_owned(),
            " padded ".to_owned(),
        ] {
            assert!(
                RecipientEntry::from_encoded(
                    &encoded,
                    RecipientClass::Software,
                    bad_label.clone(),
                    all_enrollment(),
                )
                .is_err(),
                "expected label rejection for {bad_label:?}"
            );
        }
    }

    #[test]
    fn scrypt_clamps_log_n_at_enrollment() {
        for (input, expected) in [
            (0u8, 20u8),
            (10, 20),
            (20, 20),
            (21, 21),
            (22, 22),
            (30, 22),
        ] {
            let entry = RecipientEntry::scrypt("pass".to_owned(), all_enrollment(), input).unwrap();
            assert_eq!(entry.kind, RecipientKind::Scrypt { log_n: expected });
            assert_eq!(entry.class, RecipientClass::Software);
            assert_eq!(entry.encoded, None);
        }
    }

    #[test]
    fn enrollment_field_round_trips() {
        let all = Enrollment(EnvSelector::All {
            max_tier: Tier::Critical,
        });
        assert_eq!(all.to_header_field(), "*:3");
        assert_eq!(Enrollment::parse_header_field("*:3").unwrap(), all);

        let mut map = BTreeMap::new();
        map.insert(EnvName::parse("dev").unwrap(), Tier::Ambient);
        map.insert(EnvName::parse("prod").unwrap(), Tier::Critical);
        let named = Enrollment(EnvSelector::Named(map));
        assert_eq!(named.to_header_field(), "dev:1,prod:3");
        assert_eq!(
            Enrollment::parse_header_field("dev:1,prod:3").unwrap(),
            named
        );
    }

    #[test]
    fn parse_identities_accepts_an_se_identity_file() {
        // The frozen SE identity-file shape (upstream Plugin.swift): comment
        // header, then one AGE-PLUGIN-SE-1… payload line. The comments are
        // skipped by THIS parser — the richer `# access control:` /
        // `# public key:` readers live in the CLI's stub parsers — but the
        // payload must come back as an allowlisted `se` plugin identity, or
        // the daemon can never derive the {se} pin set from a stub.
        let payload =
            crate::golden_gen::bech32::encode("age-plugin-se-", &[0x24u8; 64]).to_uppercase();
        let text = format!(
            "# created: 2026-07-20T00:00:00Z\n\
             # access control: any biometry or passcode\n\
             # public key: age1se1example\n\
             {payload}\n"
        );
        let identities = parse_identities(&text, "se-stub.txt").unwrap();
        assert_eq!(identities.len(), 1);
        match &identities[0] {
            Identity::Plugin { name, encoded } => {
                assert_eq!(name.as_str(), "se");
                assert_eq!(encoded, &payload, "the payload line rides through verbatim");
            }
            _ => panic!("an AGE-PLUGIN-SE-1 line must parse as Identity::Plugin"),
        }
    }

    #[test]
    fn parse_identities_mixed_yubikey_and_se_lines_coexist() {
        // The COEXISTENCE contract the daemon's per-cell tolerance loop relies
        // on: one stub file may name BOTH plugins, and both identities survive
        // the parse in file order (a cell wrapped to both recipients opens
        // with either identity — owner decision 'either alone unlocks'; the
        // unlock tries identities in stub order per wrap blob).
        let yubikey =
            crate::golden_gen::bech32::encode("age-plugin-yubikey-", &[0x42u8; 32]).to_uppercase();
        let se = crate::golden_gen::bech32::encode("age-plugin-se-", &[0x24u8; 64]).to_uppercase();
        let text = format!(
            "# a yubikey identity and an se identity in ONE file\n\
             {yubikey}\n\
             # public key: age1se1example\n\
             {se}\n"
        );
        let identities = parse_identities(&text, "mixed-stub.txt").unwrap();
        assert_eq!(
            identities.len(),
            2,
            "both plugin identities must survive a mixed stub file"
        );
        let names: Vec<&str> = identities
            .iter()
            .map(|identity| match identity {
                Identity::Plugin { name, .. } => name.as_str(),
                _ => panic!("a mixed stub yields only plugin identities"),
            })
            .collect();
        assert_eq!(
            names,
            vec!["yubikey", "se"],
            "file order is preserved — it decides the unlock's identity try order"
        );
    }

    #[test]
    fn enrollment_field_strictness() {
        for bad in [
            "",
            "*:0",
            "*:4",
            "*:3,dev:1", // wildcard must stand alone
            "dev:1,*:3",
            "prod:3,dev:1", // unsorted
            "dev:1,dev:2",  // duplicate
            "dev",
            "dev:12",
            "Dev:1",
        ] {
            assert!(
                matches!(
                    Enrollment::parse_header_field(bad),
                    Err(CoreError::HeaderParse { .. })
                ),
                "expected HeaderParse for {bad:?}"
            );
        }
    }
}
