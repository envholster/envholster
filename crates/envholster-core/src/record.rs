//! Records & cell types (frozen shapes: plan/04-contracts §4.3).
//!
//! serde here is manifest/display-only — HB1 stores the raw `u8`
//! discriminants; NO serde in any encrypted path (c6/c20).

use std::collections::BTreeMap;

use envholster_mem::SecretBytes;

use crate::types::{EnvName, RecipientClass, Tier};

/// P3: ONE spelling everywhere (`SshKey`); serde kebab-case pinned
/// (`"ssh-key"`), matching clap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretMode {
    Generic = 0,
    EnvVar = 1,
    SshKey = 2,
    ApiKey = 3,
}

impl SecretMode {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Over the full HB1 mode-byte range (plan/02-envelope §5).
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SecretMode::Generic),
            1 => Some(SecretMode::EnvVar),
            2 => Some(SecretMode::SshKey),
            3 => Some(SecretMode::ApiKey),
            _ => None,
        }
    }

    /// The frozen kebab-case name (ENVELOPE-SPEC §7.1) — used wherever a mode
    /// renders as text (recovery blob, manifest, CLI). Hand-written, matching
    /// the pinned serde rename: serde never touches the recovery blob, an
    /// encrypted path (c6/c20).
    pub fn kebab_name(self) -> &'static str {
        match self {
            SecretMode::Generic => "generic",
            SecretMode::EnvVar => "env-var",
            SecretMode::SshKey => "ssh-key",
            SecretMode::ApiKey => "api-key",
        }
    }
}

/// Guarantee 1–5 = G-number (D5 taxonomy: plan/06-brokers); 0 = Unassigned —
/// the P0 state: no broker exists yet, so `add` sets it unconditionally, and
/// list/status print "unassigned" verbatim, never a G-number (D5: never
/// silent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Guarantee {
    Unassigned = 0,
    BrokeredResign = 1,
    BrokeredDerived = 2,
    BrokeredHeader = 3,
    BrokeredSign = 4,
    InjectedEnv = 5,
}

impl Guarantee {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Over the full HB1 guarantee-byte range (plan/02-envelope §5).
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Guarantee::Unassigned),
            1 => Some(Guarantee::BrokeredResign),
            2 => Some(Guarantee::BrokeredDerived),
            3 => Some(Guarantee::BrokeredHeader),
            4 => Some(Guarantee::BrokeredSign),
            5 => Some(Guarantee::InjectedEnv),
            _ => None,
        }
    }

    /// The frozen kebab-case name (ENVELOPE-SPEC §7.1) — see
    /// [`SecretMode::kebab_name`]. `Unassigned` prints "unassigned" verbatim,
    /// never a G-number (D5: degradation never silent).
    pub fn kebab_name(self) -> &'static str {
        match self {
            Guarantee::Unassigned => "unassigned",
            Guarantee::BrokeredResign => "brokered-resign",
            Guarantee::BrokeredDerived => "brokered-derived",
            Guarantee::BrokeredHeader => "brokered-header",
            Guarantee::BrokeredSign => "brokered-sign",
            Guarantee::InjectedEnv => "injected-env",
        }
    }
}

/// One secret. Tier is a property of the CELL; HB1 duplicates it defensively.
#[derive(Debug)]
pub struct SecretRecord {
    pub value: SecretBytes,
    pub mode: SecretMode,
    pub guarantee: Guarantee,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub updated_at: i64,
    /// Unix seconds.
    pub rotated_at: i64,
    pub rotate_after: Option<i64>,
    /// Set by `recipient rm` (c22); NOT an HB1 grammar field — persists as the
    /// reserved metadata key `constants::METADATA_KEY_NEEDS_ROTATION`.
    pub needs_rotation: bool,
    /// Non-secret only; name-sorted in HB1; caller keys under
    /// `constants::METADATA_RESERVED_PREFIX` rejected at add/edit
    /// (`InvalidName`, P0).
    pub metadata: BTreeMap<String, String>,
}

/// Value-free listing row (`list`/`status` never emit values).
#[derive(Debug, Clone)]
pub struct SecretMeta {
    pub name: String,
    pub env: EnvName,
    pub tier: Tier,
    pub mode: SecretMode,
    pub guarantee: Guarantee,
    pub needs_rotation: bool,
    pub rotated_at: i64,
    pub rotate_after: Option<i64>,
}

/// One DEK per occupied (env × tier) cell (D1+D3); cells are lazy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId {
    pub env: EnvName,
    pub tier: Tier,
}

#[derive(Debug, Clone)]
pub struct CellStatus {
    pub id: CellId,
    pub unlocked: bool,
    pub record_count: usize,
    /// Weakest enrolled class = the REAL floor (G-A).
    pub floor: RecipientClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultUuid(pub [u8; 16]);
