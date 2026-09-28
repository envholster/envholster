//! Manifest — `envholster.toml` (plaintext, committed; plan/02-envelope §12)
//! and `envholster.local.toml` (uncommitted, gitignored, VARS ONLY — D10).
//!
//! The manifest is never vault content; it is world-readable by design and
//! treated as attacker-editable. serde + toml serve ONLY this file — never an
//! encrypted path (c6/c20). `#[serde(rename_all = "kebab-case")]` is pinned
//! (plan/02 §12); `env_var` and `max_tier` carry explicit renames because the
//! normative §12 example spells them with underscores.
//!
//! Source-of-truth rule (P2, frozen here as a check helper): the
//! AEAD-protected vault record is authoritative for tier/mode/guarantee; the
//! plaintext manifest may only RAISE effective tier, never lower it —
//! otherwise a malicious commit demotes tier 3 → tier 1 (authorization bypass
//! via git). `check_against_vault` flags every divergence.
//!
//! `${...}` interpolation (D2): resolved for vars at materialization; a
//! template referencing a secret is a COMPOSITE whose delivery collapses to
//! G5 — the composite-tier denial is enforced at delivery (later phases);
//! here composites are parsed, validated (existence, cycles), and surfaced
//! unresolved with their secret references.

use std::collections::{BTreeMap, BTreeSet};

use crate::record::{SecretMeta, SecretMode};
use crate::types::{EnvName, Tier};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest parse failed: {0}")]
    Toml(String),

    #[error("manifest schema {found} is newer than this build supports ({supported}); run a newer envholster")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("envholster.local.toml is vars-only (D10): key {key:?} is not allowed — personal secret values live in the user-scoped vault, never a plaintext local file")]
    LocalNotVarsOnly { key: String },

    #[error("invalid environment name {name:?}: {reason}")]
    InvalidEnvName { name: String, reason: String },

    #[error("environment {name:?} is declared more than once")]
    DuplicateEnvironment { name: String },

    #[error("environment {name:?} is not declared in [environments] names")]
    UndeclaredEnvironment { name: String },

    #[error("\"base\" is implicit and must not be declared or sectioned explicitly (use the top-level [vars] for the base layer)")]
    ExplicitBase,

    #[error("invalid secret name {name:?}: {reason}")]
    InvalidSecretName { name: String, reason: String },

    #[error("secret {name:?} is declared for environment {env:?} by more than one [[secret]] block — env scopes must be disjoint")]
    OverlappingSecretEnvs { name: String, env: String },

    #[error("invalid tier {tier} for secret {name:?}: tiers are 1-3")]
    InvalidTier { name: String, tier: u8 },

    #[error("secrets {first:?} and {second:?} would both be delivered as {env_var:?} in a shared environment — give one a different env_var")]
    DeliveryNameCollision {
        env_var: String,
        first: String,
        second: String,
    },

    #[error("invalid var name {name:?}: var names must match [A-Za-z_][A-Za-z0-9_]*")]
    InvalidVarName { name: String },

    #[error("agent {agent:?} has invalid max_tier {tier}: tiers are 1-3")]
    InvalidAgentTier { agent: String, tier: u8 },

    #[error("interpolation cycle through {name:?}")]
    InterpolationCycle { name: String },

    #[error("var {var:?} references unknown name {reference:?} ({kind})")]
    UnknownReference {
        var: String,
        reference: String,
        kind: &'static str,
    },

    #[error("var {var:?} has a malformed ${{...}} reference: {reason}")]
    MalformedReference { var: String, reason: String },

    #[error("invalid [exec] env_passthrough entry {entry:?}: {reason}")]
    InvalidPassthrough { entry: String, reason: String },
}

// ---------------------------------------------------------------------------
// serde model (plan/02 §12) — kebab-case pinned; §12-example spellings kept
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environments: Option<EnvironmentsSection>,
    /// Base-layer non-secret config (D2/c40).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
    /// Per-environment overlays: `[envs.<name>.vars]`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub envs: BTreeMap<String, EnvSection>,
    /// `[[secret]]` declarations. One name MAY appear in multiple blocks with
    /// DISJOINT env scopes (per-env tiers, plan/02 §12).
    #[serde(default, rename = "secret", skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretDecl>,
    /// Agent ceilings: `[agents.<name>] max_tier = N` (policy: plan/05).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, AgentSection>,
    /// Broker config stub. The `[broker.upstreams]` sub-schema is NOT frozen
    /// here — it freezes in the P2 architect contract (plan/02 §12); schema 1
    /// pins only the table's existence and its plaintext posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker: Option<BrokerSection>,
    /// `[exec] env_passthrough = [...]` — additive base-env allowlist entries
    /// for the G5 exec broker (plan/06 §7). ADD-ONLY: see [`ExecSection`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecSection>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ProjectSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct EnvironmentsSection {
    /// Declared environment names; `base` is implicit and never listed.
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct EnvSection {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
}

/// `scope = "user"` declares a secret the project needs but never contains —
/// each user satisfies it from their own user vault (plan/02 §12, c38).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretScope {
    #[default]
    Project,
    User,
}

/// Where a linked secret's VALUE resolves from (D22 Decision 1, plan/07 §7.11).
/// A committed manifest **reference, not a copy**: `[[secret]] name = "…" from =
/// "pool"` records that the value lives once in the personal pool (the
/// user-scoped vault, c38 / §7.3) and this project points at it — rotating it in
/// the pool propagates to all N projects; the value NEVER enters a committed
/// project vault. Linking is an explicit human click (a prompt-injected agent
/// cannot enumerate/drain the pool), and **tier survives the link** (a tier-2
/// pool key still needs hardware presence when used — linking is convenience,
/// not a downgrade). v1 scope: the personal pool only (Decision 2); a shared
/// team pool is deferred (P4 / D9 sync plane), so `Pool` is the only variant
/// today — the enum leaves room for it without a schema break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretSource {
    /// The machine-local personal pool (the user-scoped vault).
    Pool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SecretDecl {
    pub name: String,
    /// Empty = every declared environment (and `base`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub envs: Vec<String>,
    /// Declared tier (u8, 1-3). Under the source-of-truth rule the vault is
    /// authoritative; this may only RAISE the effective tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SecretMode>,
    /// Spelled `env_var` on disk (plan/02 §12 example — the byte authority).
    #[serde(default, rename = "env_var", skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    #[serde(default)]
    pub scope: SecretScope,
    /// D22 Decision 1 (plan/07 §7.11): a committed pool REFERENCE (`from =
    /// "pool"`). The reference commits; the personal value stays in the pool and
    /// never enters a committed project vault. `None` = a normal project secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<SecretSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AgentSection {
    /// Spelled `max_tier` on disk (plan/02 §12 example).
    #[serde(rename = "max_tier")]
    pub max_tier: u8,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BrokerSection {
    /// Opaque until the P2 contract freeze: upstream host pins + per-credential
    /// method/path allowlists. Parsed as raw TOML so schema 1 neither loses
    /// nor interprets it.
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    pub upstreams: toml::Table,
}

// ---------------------------------------------------------------------------
// [exec] — additive base-env passthrough for the G5 exec broker (plan/06 §7)
// ---------------------------------------------------------------------------

/// `[exec] env_passthrough = ["NODE_OPTIONS", "npm_*"]` — the manifest-
/// configurable half of the exec broker's deny-by-default base-env allowlist
/// (plan/06 §7). Real-world node/Next.js/npm projects need a handful of parent
/// vars (`NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS`, `npm_*`, `HTTP(S)_PROXY`) that
/// the frozen base allowlist deliberately does not carry; this is the opt-in.
///
/// SECURITY POSTURE — this list is **strictly additive and value-free**:
///   * It can only ADD names to the effective allowlist. It can never remove a
///     base entry, never widen `SSH_AUTH_SOCK`'s conditional rule, and never
///     turn off deny-by-default (a bare `"*"` is a parse error, and a glob must
///     carry a prefix of at least [`MIN_PASSTHROUGH_PREFIX`] characters).
///   * A listed name passes the **parent process's** value through, verbatim.
///     The manifest can NEVER set or inject a value here — that is what
///     `[vars]` is for. There is no `name = value` form by construction: the
///     schema is a list of strings, not a table.
///   * A passthrough name that collides with an injected secret LOSES: the
///     injected secret always wins, and the collision is logged by the daemon
///     (name only, never a value). See [`EnvPassthrough::matches`] callers in
///     `envholster-broker-exec`.
///   * [`FORBIDDEN_PASSTHROUGH`] names/prefixes are refused outright. The
///     manifest is committed, world-readable and treated as ATTACKER-EDITABLE
///     (see this module's header); letting a commit add `DYLD_INSERT_LIBRARIES`
///     or `LD_PRELOAD` to the brokered child's environment would be arbitrary
///     code injection into a process holding tier-1 secrets. `SSH_AUTH_SOCK`
///     stays conditional (broker-owned) and `ENVHOLSTER_*` stays scrubbed so a
///     commit cannot redirect the CLI/daemon socket.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ExecSection {
    /// Spelled `env_passthrough` on disk (underscores, matching `env_var` /
    /// `max_tier`). Exact names and trailing-`*` prefix globs (`npm_*`),
    /// mirroring the base allowlist's built-in `LC_*` prefix rule.
    #[serde(
        default,
        rename = "env_passthrough",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub env_passthrough: Vec<String>,
}

/// Minimum prefix length for a trailing-glob passthrough entry. `"*"` (match
/// everything — deny-by-default off) and `"A*"` (match a whole letter of the
/// namespace) are both refused; `"np*"` is the shortest accepted form.
pub const MIN_PASSTHROUGH_PREFIX: usize = 2;

/// Names/prefixes a manifest may NEVER add to the child environment, whatever
/// it asks for. Entries ending in `_` are prefix rules.
///
///   * `DYLD_` / `LD_` — dynamic-linker injection (`DYLD_INSERT_LIBRARIES`,
///     `LD_PRELOAD`): arbitrary code execution inside a process that is about
///     to hold injected tier-1 secrets. This is the security-relevant scrub the
///     manifest must never be able to remove.
///   * `ENVHOLSTER_` — the CLI/daemon's own configuration surface (socket path,
///     binary overrides). A committed manifest must not be able to redirect it.
///   * `SSH_AUTH_SOCK` — broker-owned and conditional (allowed only when it
///     points at the sign-only agent broker, plan/06 §6). Passthrough would
///     make it unconditional and hand the child the user's real agent.
pub const FORBIDDEN_PASSTHROUGH: &[&str] = &["DYLD_", "LD_", "ENVHOLSTER_", "SSH_AUTH_SOCK"];

/// One parsed, validated passthrough rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PassthroughRule {
    /// Exact variable name.
    Exact(String),
    /// Trailing-glob prefix (`npm_*` → `Prefix("npm_")`).
    Prefix(String),
}

/// The parsed `[exec] env_passthrough` list: an ADD-ONLY overlay on the exec
/// broker's deny-by-default base-env allowlist. Construct with
/// [`EnvPassthrough::parse`] (or [`Manifest::env_passthrough`]); the default is
/// empty, which reproduces the frozen base-only behavior exactly — an absent or
/// empty `[exec]` block is a no-op, never a regression.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvPassthrough {
    rules: Vec<PassthroughRule>,
}

impl EnvPassthrough {
    /// Parse + validate raw manifest entries. See [`ExecSection`] for the rules.
    pub fn parse(entries: &[String]) -> Result<Self, ManifestError> {
        let mut rules = Vec::with_capacity(entries.len());
        for raw in entries {
            rules.push(parse_passthrough_entry(raw)?);
        }
        Ok(EnvPassthrough { rules })
    }

    /// True when `name` is covered by an exact entry or a prefix glob. This only
    /// ever ADMITS a name for parent-value passthrough; it can never deny one
    /// the base allowlist already admits, and it never carries a value.
    pub fn matches(&self, name: &str) -> bool {
        self.rules.iter().any(|rule| match rule {
            PassthroughRule::Exact(exact) => exact == name,
            PassthroughRule::Prefix(prefix) => name.starts_with(prefix.as_str()),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The entries in their on-disk spelling, for `check`/`doctor` display.
    pub fn display_entries(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|rule| match rule {
                PassthroughRule::Exact(exact) => exact.clone(),
                PassthroughRule::Prefix(prefix) => format!("{prefix}*"),
            })
            .collect()
    }
}

fn parse_passthrough_entry(raw: &str) -> Result<PassthroughRule, ManifestError> {
    let invalid = |reason: &str| ManifestError::InvalidPassthrough {
        entry: raw.to_owned(),
        reason: reason.to_owned(),
    };

    if raw.is_empty() {
        return Err(invalid("entry is empty"));
    }
    // `=` would corrupt `KEY=VALUE` framing (and is how a caller would try to
    // smuggle a VALUE through a name-only list); NUL would truncate the C
    // string the broker builds.
    if raw.contains('=') {
        return Err(invalid(
            "entry contains '='; env_passthrough lists NAMES only and passes the parent's \
             value through — it can never set a value (use [vars] for that)",
        ));
    }
    if raw.contains('\0') {
        return Err(invalid("entry contains a NUL byte"));
    }

    let (stem, is_glob) = match raw.strip_suffix('*') {
        Some(prefix) => {
            if prefix.len() < MIN_PASSTHROUGH_PREFIX {
                return Err(invalid(
                    "glob prefix is too short; a passthrough glob needs at least \
                     2 characters before '*' (a bare '*' would disable the \
                     deny-by-default base-env allowlist)",
                ));
            }
            (prefix, true)
        }
        None => (raw, false),
    };
    // Interior '*' (e.g. "np*m" or "a**") is not a supported glob form.
    if stem.contains('*') {
        return Err(invalid(
            "'*' is only supported as a single trailing glob (e.g. \"npm_*\")",
        ));
    }
    // Same charset as every other env-var name in the manifest.
    validate_var_name(stem).map_err(|_| ManifestError::InvalidPassthrough {
        entry: raw.to_owned(),
        reason: "must be an environment variable name ([A-Za-z_][A-Za-z0-9_]*), \
                     optionally with a single trailing '*'"
            .to_owned(),
    })?;

    for forbidden in FORBIDDEN_PASSTHROUGH {
        let hit = if forbidden.ends_with('_') {
            // Prefix rule: refuse anything under it, and refuse a glob whose own
            // prefix straddles it ("DY*" would otherwise cover "DYLD_PRINT_*").
            stem.starts_with(forbidden) || (is_glob && forbidden.starts_with(stem))
        } else {
            // Exact rule: refuse the name, and refuse a glob that would cover it.
            stem == *forbidden || (is_glob && forbidden.starts_with(stem))
        };
        if hit {
            return Err(invalid(&format!(
                "{forbidden} is never passthrough-able: it is a security-relevant scrub \
                 the manifest must not be able to remove (linker injection / broker-owned \
                 sockets / envholster's own config surface)"
            )));
        }
    }

    Ok(if is_glob {
        PassthroughRule::Prefix(stem.to_owned())
    } else {
        PassthroughRule::Exact(stem.to_owned())
    })
}

// ---------------------------------------------------------------------------
// Local override — vars ONLY (D10)
// ---------------------------------------------------------------------------

/// `envholster.local.toml`: uncommitted, gitignored, `[vars]` only — never
/// secret values, never structure (D10).
#[derive(Debug, Clone, Default)]
pub struct LocalOverride {
    pub vars: BTreeMap<String, String>,
}

impl LocalOverride {
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        // Structural gate first: ANY key other than `vars` is refused with
        // the D10 message (a serde unknown-field error would name serde, not
        // the rule).
        let table: toml::Table = text
            .parse()
            .map_err(|e: toml::de::Error| ManifestError::Toml(e.to_string()))?;
        for key in table.keys() {
            if key != "vars" {
                return Err(ManifestError::LocalNotVarsOnly { key: key.clone() });
            }
        }
        let mut vars = BTreeMap::new();
        if let Some(value) = table.get("vars") {
            let section = value
                .as_table()
                .ok_or_else(|| ManifestError::Toml("[vars] must be a table".to_owned()))?;
            for (name, value) in section {
                let value = value
                    .as_str()
                    .ok_or_else(|| ManifestError::Toml(format!("var {name:?} must be a string")))?;
                validate_var_name(name)?;
                vars.insert(name.clone(), value.to_owned());
            }
        }
        Ok(LocalOverride { vars })
    }
}

// ---------------------------------------------------------------------------
// Parse + validate
// ---------------------------------------------------------------------------

fn validate_var_name(name: &str) -> Result<(), ManifestError> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && matches!(bytes[0], b'A'..=b'Z' | b'a'..=b'z' | b'_')
        && bytes[1..]
            .iter()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(ManifestError::InvalidVarName {
            name: name.to_owned(),
        })
    }
}

impl Manifest {
    pub const SCHEMA: u32 = 1;

    /// Parses and fully validates `envholster.toml`.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        Self::parse_inner(text, true)
    }

    /// Permissive parse for the daemon-side authorize() lookup (P1 fill-in,
    /// spikes/P1-CONTRACT.md §8, plan/05 §5.6). Runs every validation EXCEPT
    /// the disjoint-per-env-secret-scope rule: overlapping `[[secret]]` blocks
    /// for one name (which strict `parse` rejects as a `check`-time authoring
    /// error) are tolerated, and the daemon resolves the effective declared
    /// tier as the MAXIMUM across all matching blocks via
    /// [`Manifest::declared_max_tier`] — the manifest may only RAISE a cell's
    /// effective tier, never lower it, so taking the max is the fail-safe
    /// reading. This lets the broker enforce authorize() against a manifest an
    /// operator has (e.g.) both `add`ed and hand-edited without the daemon
    /// refusing to load it. Strict `parse` (used by `check`) still flags the
    /// overlap as an authoring divergence.
    pub fn parse_permissive(text: &str) -> Result<Self, ManifestError> {
        Self::parse_inner(text, false)
    }

    fn parse_inner(text: &str, strict: bool) -> Result<Self, ManifestError> {
        // Schema check FIRST, from the raw table, so a newer manifest fails
        // with the migration message instead of an unknown-field error.
        let raw: toml::Table = text
            .parse()
            .map_err(|e: toml::de::Error| ManifestError::Toml(e.to_string()))?;
        if let Some(found) = raw.get("schema").and_then(toml::Value::as_integer) {
            if found > i64::from(Self::SCHEMA) {
                return Err(ManifestError::UnsupportedSchema {
                    found: u32::try_from(found).unwrap_or(u32::MAX),
                    supported: Self::SCHEMA,
                });
            }
        }
        let manifest: Manifest = toml::Table::try_into(raw)
            .map_err(|e: toml::de::Error| ManifestError::Toml(e.to_string()))?;
        manifest.validate(strict)?;
        Ok(manifest)
    }

    fn validate(&self, strict: bool) -> Result<(), ManifestError> {
        if self.schema != Self::SCHEMA {
            return Err(ManifestError::UnsupportedSchema {
                found: self.schema,
                supported: Self::SCHEMA,
            });
        }

        // Environments: valid names, no duplicates, base implicit.
        let mut declared: BTreeSet<&str> = BTreeSet::new();
        if let Some(environments) = &self.environments {
            for name in &environments.names {
                if name == crate::constants::BASE_ENV {
                    return Err(ManifestError::ExplicitBase);
                }
                EnvName::parse(name).map_err(|_| ManifestError::InvalidEnvName {
                    name: name.clone(),
                    reason: "environment names must match [a-z0-9][a-z0-9_-]{0,31}".to_owned(),
                })?;
                if !declared.insert(name) {
                    return Err(ManifestError::DuplicateEnvironment { name: name.clone() });
                }
            }
        }

        // [envs.<name>] sections reference declared environments only.
        for name in self.envs.keys() {
            if name == crate::constants::BASE_ENV {
                return Err(ManifestError::ExplicitBase);
            }
            if !declared.contains(name.as_str()) {
                return Err(ManifestError::UndeclaredEnvironment { name: name.clone() });
            }
        }

        // Var names, everywhere.
        for name in self
            .vars
            .keys()
            .chain(self.envs.values().flat_map(|section| section.vars.keys()))
        {
            validate_var_name(name)?;
        }

        // Secrets: name charset, valid+declared envs, valid tier, disjoint
        // env scopes per name (plan/02 §12: overlap is a `check` error).
        let mut claimed: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut wildcard: BTreeSet<&str> = BTreeSet::new();
        for decl in &self.secrets {
            crate::hb1::validate_secret_name(&decl.name).map_err(|_| {
                ManifestError::InvalidSecretName {
                    name: decl.name.clone(),
                    reason: "secret names must match [A-Za-z0-9_.-]{1,128}".to_owned(),
                }
            })?;
            if let Some(tier) = decl.tier {
                if Tier::try_from_u8(tier).is_none() {
                    return Err(ManifestError::InvalidTier {
                        name: decl.name.clone(),
                        tier,
                    });
                }
            }
            if let Some(env_var) = &decl.env_var {
                validate_var_name(env_var)?;
            }
            let scope = claimed.entry(decl.name.as_str()).or_default();
            if decl.envs.is_empty() {
                // Applies to all envs: overlaps with ANY other block. In
                // permissive mode (daemon authorize() load) the overlap is
                // tolerated — `declared_max_tier` resolves it fail-safe.
                let overlaps = !scope.is_empty() || !wildcard.insert(decl.name.as_str());
                if strict && overlaps {
                    return Err(ManifestError::OverlappingSecretEnvs {
                        name: decl.name.clone(),
                        env: "*".to_owned(),
                    });
                }
            } else {
                if strict && wildcard.contains(decl.name.as_str()) {
                    return Err(ManifestError::OverlappingSecretEnvs {
                        name: decl.name.clone(),
                        env: "*".to_owned(),
                    });
                }
                for env in &decl.envs {
                    if env != crate::constants::BASE_ENV && !declared.contains(env.as_str()) {
                        return Err(ManifestError::UndeclaredEnvironment { name: env.clone() });
                    }
                    if !scope.insert(env) && strict {
                        return Err(ManifestError::OverlappingSecretEnvs {
                            name: decl.name.clone(),
                            env: env.clone(),
                        });
                    }
                }
            }
        }

        // Two effective secrets must never be delivered under one name in any
        // environment (an `env_var` alias colliding with another alias, or
        // with another secret's own name): `run` and `export` would each pick
        // one, and not the same one. Checked per environment on the EFFECTIVE
        // delivery map, base fallback included: a prod secret aliased to `B`
        // collides with the base secret `B` that prod inherits.
        if strict {
            let mut envs: Vec<EnvName> = vec![EnvName::base()];
            for name in self.environment_names() {
                if let Ok(env) = EnvName::parse(name) {
                    envs.push(env);
                }
            }
            for env in &envs {
                let mut seen: BTreeMap<String, &str> = BTreeMap::new();
                for decl in &self.secrets {
                    let governs = self.secret_decl(&decl.name, env).is_some()
                        || self.secret_decl(&decl.name, &EnvName::base()).is_some();
                    if !governs {
                        continue;
                    }
                    let delivery = self.delivery_name(&decl.name, env);
                    if let Some(other) = seen.insert(delivery.clone(), &decl.name) {
                        if other != decl.name {
                            return Err(ManifestError::DeliveryNameCollision {
                                env_var: delivery,
                                first: other.to_owned(),
                                second: decl.name.clone(),
                            });
                        }
                    }
                }
            }
        }

        // [exec] env_passthrough: names/globs are validated (and the forbidden
        // scrubs refused) at PARSE time, so an invalid entry can never reach the
        // exec broker — `Manifest::env_passthrough` is infallible thereafter.
        if let Some(exec) = &self.exec {
            EnvPassthrough::parse(&exec.env_passthrough)?;
        }

        // Agent ceilings.
        for (agent, section) in &self.agents {
            if Tier::try_from_u8(section.max_tier).is_none() {
                return Err(ManifestError::InvalidAgentTier {
                    agent: agent.clone(),
                    tier: section.max_tier,
                });
            }
        }
        Ok(())
    }

    /// The validated `[exec] env_passthrough` overlay for the G5 exec broker.
    ///
    /// ADD-ONLY (see [`ExecSection`]): these names are additionally admitted
    /// from the PARENT environment on top of the frozen deny-by-default base
    /// allowlist. They carry no value of their own, cannot remove a base entry
    /// or a security scrub, and lose to an injected secret of the same name.
    ///
    /// Infallible: `validate` already rejected any bad entry at parse time, so
    /// a `Manifest` in hand always has a parseable list. An absent or empty
    /// `[exec]` block yields the empty overlay — identical behavior to the
    /// frozen base-only allowlist.
    pub fn env_passthrough(&self) -> EnvPassthrough {
        self.exec
            .as_ref()
            .map(|exec| EnvPassthrough::parse(&exec.env_passthrough).unwrap_or_default())
            .unwrap_or_default()
    }

    /// Declared environment names (excludes the implicit `base`).
    pub fn environment_names(&self) -> Vec<&str> {
        self.environments
            .as_ref()
            .map(|e| e.names.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// The `[[secret]]` block governing `name` in `env`, honoring disjoint
    /// per-env scopes: an env-scoped block wins for its envs; a block with no
    /// `envs` list covers everything else.
    /// The environment variable `name` is delivered as in `env`: the
    /// `env_var` of the declaration governing (name, env), else of the base
    /// declaration `env` falls back to, else the name itself. The one rule
    /// `run`, `export`, `get` and the collision check all use.
    pub fn delivery_name(&self, name: &str, env: &EnvName) -> String {
        self.secret_decl(name, env)
            .or_else(|| self.secret_decl(name, &EnvName::base()))
            .and_then(|d| d.env_var.clone())
            .unwrap_or_else(|| name.to_owned())
    }

    pub fn secret_decl(&self, name: &str, env: &EnvName) -> Option<&SecretDecl> {
        let mut wildcard_match: Option<&SecretDecl> = None;
        for decl in &self.secrets {
            if decl.name != name {
                continue;
            }
            if decl.envs.is_empty() {
                wildcard_match = Some(decl);
            } else if decl.envs.iter().any(|e| e == env.as_str()) {
                return Some(decl);
            }
        }
        wildcard_match
    }

    /// Daemon authorize() lookup (P1, spikes/P1-CONTRACT.md §8): is `name`
    /// declared for `env`, and — across EVERY `[[secret]]` block that governs
    /// (name, env), including overlapping ones a permissive parse tolerated —
    /// the MAXIMUM declared tier. Returns `(declared, max_tier)`. Taking the
    /// max is the fail-safe reading of the source-of-truth rule (plan/02 §12,
    /// [`effective_tier`]): the manifest may only RAISE a cell's effective
    /// tier, so when two blocks disagree the higher tier wins and a secret is
    /// never silently under-classified. A block whose `envs` is empty is a
    /// wildcard that governs every env; a block naming `env` governs it too.
    pub fn declared_max_tier(&self, name: &str, env: &EnvName) -> (bool, Option<Tier>) {
        let mut declared = false;
        let mut max_tier: Option<Tier> = None;
        for decl in &self.secrets {
            if decl.name != name {
                continue;
            }
            let governs = decl.envs.is_empty() || decl.envs.iter().any(|e| e == env.as_str());
            if !governs {
                continue;
            }
            declared = true;
            if let Some(tier) = decl.tier.and_then(Tier::try_from_u8) {
                max_tier = Some(match max_tier {
                    Some(current) if current.as_u8() >= tier.as_u8() => current,
                    _ => tier,
                });
            }
        }
        (declared, max_tier)
    }

    // -----------------------------------------------------------------------
    // Precedence + ${} interpolation (D2; plan/02 §12, plan/07 §7.1–7.2)
    // -----------------------------------------------------------------------

    /// The var layers for `env` MERGED but NOT resolved — base `[vars]` →
    /// `[envs.<env>.vars]` → local `[vars]`, later layers winning per key,
    /// every `${...}` left exactly as written. This is the raw merge
    /// [`Self::resolve_vars_lenient`] re-resolves per-var when
    /// [`Self::resolve_vars`] refuses the manifest (an unknown reference, a
    /// cycle): the app still gets every var, and the delivery seam's lenient
    /// expander leaves an unresolvable reference literal so it fails loudly
    /// at the consumer instead of taking the whole set down. An undeclared
    /// `env` simply contributes nothing here — no error.
    pub fn layered_vars(
        &self,
        env: Option<&EnvName>,
        local: Option<&LocalOverride>,
    ) -> BTreeMap<String, String> {
        let mut raw: BTreeMap<String, String> = self.vars.clone();
        if let Some(env) = env {
            if let Some(section) = self.envs.get(env.as_str()) {
                for (k, v) in &section.vars {
                    raw.insert(k.clone(), v.clone());
                }
            }
        }
        if let Some(local) = local {
            for (k, v) in &local.vars {
                raw.insert(k.clone(), v.clone());
            }
        }
        raw
    }

    /// Merges the var layers for `env` — base `[vars]` → `[envs.<env>.vars]`
    /// → local `[vars]` (later layers win per key) — and resolves `${...}`
    /// references. Var-only templates resolve to `VarValue::Plain`; templates
    /// referencing secrets are surfaced as `VarValue::Composite` with their
    /// secret references (values live in the vault; composite delivery — and
    /// its tier rule — is enforced at delivery, later phases). Cycles and
    /// unknown names are hard errors.
    pub fn resolve_vars(
        &self,
        env: Option<&EnvName>,
        local: Option<&LocalOverride>,
    ) -> Result<BTreeMap<String, VarValue>, ManifestError> {
        if let Some(env) = env {
            if env.as_str() != crate::constants::BASE_ENV
                && !self.environment_names().contains(&env.as_str())
            {
                return Err(ManifestError::UndeclaredEnvironment {
                    name: env.as_str().to_owned(),
                });
            }
        }

        // Layered merge (frozen precedence, deliberately small).
        let mut raw: BTreeMap<String, String> = self.vars.clone();
        if let Some(env) = env {
            if let Some(section) = self.envs.get(env.as_str()) {
                for (k, v) in &section.vars {
                    raw.insert(k.clone(), v.clone());
                }
            }
        }
        if let Some(local) = local {
            for (k, v) in &local.vars {
                raw.insert(k.clone(), v.clone());
            }
        }

        let mut resolver = Resolver {
            manifest: self,
            env,
            raw: &raw,
            resolved: BTreeMap::new(),
            visiting: Vec::new(),
        };
        for name in raw.keys() {
            resolver.resolve(name)?;
        }
        Ok(resolver.resolved)
    }

    /// The per-variable fallback for a manifest [`Self::resolve_vars`]
    /// refused (an unknown reference, a cycle, a malformed `${...}`): each
    /// var resolves on its own, so one bad reference costs only the vars
    /// that depend on it. A var that resolves keeps its resolved value — a
    /// valid `${secret:NAME}` composite still materializes at delivery —
    /// and one that does not falls back to its raw layered text as
    /// `VarValue::Plain`, left for the delivery seam's lenient expander.
    /// An undeclared `env` must be refused by the caller first (here its
    /// section simply contributes nothing, like [`Self::layered_vars`]).
    pub fn resolve_vars_lenient(
        &self,
        env: Option<&EnvName>,
        local: Option<&LocalOverride>,
    ) -> BTreeMap<String, VarValue> {
        let raw = self.layered_vars(env, local);
        let mut out = BTreeMap::new();
        for (name, template) in &raw {
            // A fresh resolver per var: a failure must not poison the cache
            // another var's clean resolution would read.
            let mut resolver = Resolver {
                manifest: self,
                env,
                raw: &raw,
                resolved: BTreeMap::new(),
                visiting: Vec::new(),
            };
            let value = resolver
                .resolve(name)
                .unwrap_or_else(|_| VarValue::Plain(template.clone()));
            out.insert(name.clone(), value);
        }
        out
    }

    /// True iff `name` is declared as a secret reachable from `env` (its own
    /// block envs, a wildcard block, or `base` — secret resolution falls back
    /// to base, plan/02 §12).
    fn secret_declared_for(&self, name: &str, env: Option<&EnvName>) -> bool {
        self.secrets.iter().any(|decl| {
            decl.name == name
                && (decl.envs.is_empty()
                    || decl.envs.iter().any(|e| {
                        e == crate::constants::BASE_ENV || env.is_some_and(|env| e == env.as_str())
                    }))
        })
    }

    // -----------------------------------------------------------------------
    // Source-of-truth check helper (P2 rule, frozen P0; plan/02 §12)
    // -----------------------------------------------------------------------

    /// Flags every vault/manifest divergence for the secrets visible in
    /// `vault_list` (the caller decides which cells were unlockable):
    /// declared-but-no-value, value-but-undeclared, tier mismatch, mode
    /// mismatch. The vault is authoritative — see [`effective_tier`].
    pub fn check_against_vault(&self, vault_list: &[SecretMeta]) -> Vec<CheckFinding> {
        let mut findings = Vec::new();

        // Vault → manifest: every stored value must be declared. The base
        // cell is fallback storage for every environment (plan/02 §12), so a
        // base record is declared when ANY block names it; a record in
        // another env needs a block governing that env.
        for meta in vault_list {
            let governing = self.secret_decl(&meta.name, &meta.env).or_else(|| {
                (meta.env.as_str() == crate::constants::BASE_ENV)
                    .then(|| self.secrets.iter().find(|d| d.name == meta.name))
                    .flatten()
            });
            match governing {
                None => findings.push(CheckFinding::ValueButUndeclared {
                    name: meta.name.clone(),
                    env: meta.env.clone(),
                }),
                Some(decl) => {
                    if let Some(tier) = decl.tier {
                        if tier != meta.tier.as_u8() {
                            findings.push(CheckFinding::TierDivergence {
                                name: meta.name.clone(),
                                env: meta.env.clone(),
                                vault: meta.tier,
                                manifest: tier,
                                // The dangerous direction: a manifest can
                                // never LOWER the vault's tier (P2 rule).
                                attempted_lowering: tier < meta.tier.as_u8(),
                            });
                        }
                    }
                    if let Some(mode) = decl.mode {
                        if mode != meta.mode {
                            findings.push(CheckFinding::ModeDivergence {
                                name: meta.name.clone(),
                                env: meta.env.clone(),
                                vault: meta.mode,
                                manifest: mode,
                            });
                        }
                    }
                }
            }
        }

        // Manifest → vault: every project-scoped declaration needs a value in
        // each env it names (user-scoped secrets live in user vaults — c38).
        for decl in &self.secrets {
            if decl.scope == SecretScope::User {
                continue;
            }
            let envs: Vec<String> = if decl.envs.is_empty() {
                std::iter::once(crate::constants::BASE_ENV.to_owned())
                    .chain(self.environment_names().iter().map(|s| (*s).to_owned()))
                    .collect()
            } else {
                decl.envs.clone()
            };
            for env in envs {
                let present = vault_list
                    .iter()
                    .any(|meta| meta.name == decl.name && meta.env.as_str() == env);
                // Secret resolution falls back to base (plan/02 §12): a value
                // in base satisfies a declaration for any env — but only at
                // that env's declared strength. A base record weaker than
                // what this env declares is a divergence for THIS env: the
                // doors refuse to deliver it, and doctor must say so rather
                // than certify the pair as agreeing.
                let base_record = vault_list.iter().find(|meta| {
                    meta.name == decl.name && meta.env.as_str() == crate::constants::BASE_ENV
                });
                if present {
                    continue;
                }
                match base_record {
                    None => findings.push(CheckFinding::DeclaredButNoValue {
                        name: decl.name.clone(),
                        env: env.clone(),
                    }),
                    Some(meta) if env != crate::constants::BASE_ENV => {
                        if let Some(tier) = decl.tier {
                            if tier > meta.tier.as_u8() {
                                findings.push(CheckFinding::TierDivergence {
                                    name: decl.name.clone(),
                                    env: EnvName::parse(&env).unwrap_or_else(|_| EnvName::base()),
                                    vault: meta.tier,
                                    manifest: tier,
                                    attempted_lowering: false,
                                });
                            }
                        }
                        if let Some(mode) = decl.mode {
                            if mode != meta.mode {
                                findings.push(CheckFinding::ModeDivergence {
                                    name: decl.name.clone(),
                                    env: EnvName::parse(&env).unwrap_or_else(|_| EnvName::base()),
                                    vault: meta.mode,
                                    manifest: mode,
                                });
                            }
                        }
                    }
                    Some(_) => {}
                }
            }
        }
        findings
    }
}

/// The vault record is authoritative; the manifest may only RAISE the
/// effective tier, never lower it (plan/02 §12, P2 source-of-truth rule).
pub fn effective_tier(vault: Tier, manifest: Option<Tier>) -> Tier {
    match manifest {
        Some(declared) if declared > vault => declared,
        _ => vault,
    }
}

/// One resolved var (plan/07 §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarValue {
    /// Fully resolved from vars alone.
    Plain(String),
    /// References at least one secret: unresolved at this layer (the value
    /// must materialize at delivery, collapsing to G5 — plan/02 §12).
    Composite {
        /// The template with var references already substituted; secret
        /// references left verbatim as `${secret:NAME}`.
        template: String,
        /// Secret names the template references (directly or via other vars).
        secret_refs: BTreeSet<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckFinding {
    DeclaredButNoValue {
        name: String,
        env: String,
    },
    ValueButUndeclared {
        name: String,
        env: EnvName,
    },
    TierDivergence {
        name: String,
        env: EnvName,
        vault: Tier,
        manifest: u8,
        /// True when the manifest tries to LOWER the vault tier — the
        /// authorization-bypass direction the P2 rule forbids.
        attempted_lowering: bool,
    },
    ModeDivergence {
        name: String,
        env: EnvName,
        vault: SecretMode,
        manifest: SecretMode,
    },
}

// ---------------------------------------------------------------------------
// ${} resolution
// ---------------------------------------------------------------------------

struct Resolver<'a> {
    manifest: &'a Manifest,
    env: Option<&'a EnvName>,
    raw: &'a BTreeMap<String, String>,
    resolved: BTreeMap<String, VarValue>,
    visiting: Vec<String>,
}

impl Resolver<'_> {
    fn resolve(&mut self, name: &str) -> Result<VarValue, ManifestError> {
        if let Some(done) = self.resolved.get(name) {
            return Ok(done.clone());
        }
        if self.visiting.iter().any(|v| v == name) {
            return Err(ManifestError::InterpolationCycle {
                name: name.to_owned(),
            });
        }
        self.visiting.push(name.to_owned());
        let template = self.raw.get(name).expect("resolve() called on known var");
        let value = self.resolve_template(name, template)?;
        self.visiting.pop();
        self.resolved.insert(name.to_owned(), value.clone());
        Ok(value)
    }

    fn resolve_template(&mut self, var: &str, template: &str) -> Result<VarValue, ManifestError> {
        let mut out = String::with_capacity(template.len());
        let mut secret_refs: BTreeSet<String> = BTreeSet::new();
        let mut rest = template;
        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let end = after
                .find('}')
                .ok_or_else(|| ManifestError::MalformedReference {
                    var: var.to_owned(),
                    reason: "unclosed ${".to_owned(),
                })?;
            let reference = &after[..end];
            rest = &after[end + 1..];

            let (kind, target) = match reference.split_once(':') {
                Some(("var", t)) => ("var", t),
                Some(("secret", t)) => ("secret", t),
                Some((other, _)) => {
                    return Err(ManifestError::MalformedReference {
                        var: var.to_owned(),
                        reason: format!("unknown reference kind {other:?} (use var: or secret:)"),
                    })
                }
                None => ("", reference),
            };
            if target.is_empty() {
                return Err(ManifestError::MalformedReference {
                    var: var.to_owned(),
                    reason: "empty reference name".to_owned(),
                });
            }

            let is_var = self.raw.contains_key(target);
            let is_secret = self.manifest.secret_declared_for(target, self.env);
            let resolve_as_var = match kind {
                "var" => {
                    if !is_var {
                        return Err(ManifestError::UnknownReference {
                            var: var.to_owned(),
                            reference: target.to_owned(),
                            kind: "no such var",
                        });
                    }
                    true
                }
                "secret" => {
                    if !is_secret {
                        return Err(ManifestError::UnknownReference {
                            var: var.to_owned(),
                            reference: target.to_owned(),
                            kind: "no such declared secret",
                        });
                    }
                    false
                }
                // Bare ${NAME}: vars first, then declared secrets.
                _ => {
                    if is_var {
                        true
                    } else if is_secret {
                        false
                    } else {
                        return Err(ManifestError::UnknownReference {
                            var: var.to_owned(),
                            reference: target.to_owned(),
                            kind: "neither a var nor a declared secret",
                        });
                    }
                }
            };

            if resolve_as_var {
                match self.resolve(target)? {
                    VarValue::Plain(value) => out.push_str(&value),
                    VarValue::Composite {
                        template,
                        secret_refs: inner,
                    } => {
                        // Composite-ness propagates: the referencing var
                        // inherits the unresolved secret references.
                        out.push_str(&template);
                        secret_refs.extend(inner);
                    }
                }
            } else {
                // Secret reference: left verbatim in canonical form.
                out.push_str("${secret:");
                out.push_str(target);
                out.push('}');
                secret_refs.insert(target.to_owned());
            }
        }
        out.push_str(rest);

        if secret_refs.is_empty() {
            Ok(VarValue::Plain(out))
        } else {
            Ok(VarValue::Composite {
                template: out,
                secret_refs,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Guarantee;

    /// The plan/02 §12 example, normalized to real TOML (the plan figure
    /// compresses multiple keys per line for reading width).
    const PLAN_EXAMPLE: &str = r#"
schema = 1

[project]
name = "acme-api"

[environments]
names = ["dev", "staging", "prod"]

[vars]
LOG_LEVEL = "info"
DATABASE_URL = "postgres://app:${DB_PASSWORD}@${DB_HOST}/acme"

[envs.prod.vars]
DB_HOST = "db.prod.internal"

[[secret]]
name = "DB_PASSWORD"
envs = ["dev"]
tier = 1
mode = "api-key"
env_var = "DB_PASSWORD"

[[secret]]
name = "DB_PASSWORD"
envs = ["prod"]
tier = 3
mode = "api-key"
env_var = "DB_PASSWORD"

[[secret]]
name = "github_ssh"
scope = "user"

[agents.claude]
max_tier = 1

[broker.upstreams]
"#;

    fn env(name: &str) -> EnvName {
        EnvName::parse(name).unwrap()
    }

    #[test]
    fn plan_example_parses_and_validates() {
        let manifest = Manifest::parse(PLAN_EXAMPLE).unwrap();
        assert_eq!(manifest.schema, 1);
        assert_eq!(
            manifest.project.as_ref().unwrap().name.as_deref(),
            Some("acme-api")
        );
        assert_eq!(manifest.environment_names(), vec!["dev", "staging", "prod"]);
        assert_eq!(manifest.vars["LOG_LEVEL"], "info");
        assert_eq!(manifest.secrets.len(), 3);
        assert_eq!(manifest.agents["claude"].max_tier, 1);
        assert_eq!(manifest.secrets[2].scope, SecretScope::User);
        assert_eq!(manifest.secrets[0].mode, Some(SecretMode::ApiKey));

        // Per-env tier via repeated disjoint blocks (plan/02 §12).
        let dev_decl = manifest.secret_decl("DB_PASSWORD", &env("dev")).unwrap();
        assert_eq!(dev_decl.tier, Some(1));
        let prod_decl = manifest.secret_decl("DB_PASSWORD", &env("prod")).unwrap();
        assert_eq!(prod_decl.tier, Some(3));
        // github_ssh has no envs list: wildcard match everywhere.
        assert!(manifest
            .secret_decl("github_ssh", &env("staging"))
            .is_some());
    }

    #[test]
    fn pool_reference_from_field_parses_and_round_trips() {
        // D22 Decision 1 (plan/07 §7.11): `from = "pool"` is a committed
        // reference; the value never commits. A normal secret has `from = None`.
        let text = r#"
schema = 1
[[secret]]
name = "STRIPE_SECRET_KEY"
tier = 2
mode = "api-key"
from = "pool"

[[secret]]
name = "PROJECT_TOKEN"
tier = 1
"#;
        let manifest = Manifest::parse(text).unwrap();
        let pooled = &manifest.secrets[0];
        assert_eq!(pooled.name, "STRIPE_SECRET_KEY");
        assert_eq!(pooled.from, Some(SecretSource::Pool));
        // A normal project secret carries no pool reference.
        assert_eq!(manifest.secrets[1].from, None);
        // The `from = "pool"` spelling survives serialization.
        let rendered = toml::to_string(&manifest).unwrap();
        assert!(
            rendered.contains("from = \"pool\""),
            "pool reference must round-trip: {rendered}"
        );
        let reparsed = Manifest::parse(&rendered).unwrap();
        assert_eq!(reparsed.secrets[0].from, Some(SecretSource::Pool));
        // An unknown source value is refused (serde enum), not silently accepted.
        assert!(
            Manifest::parse("schema = 1\n[[secret]]\nname = \"K\"\nfrom = \"nope\"\n").is_err()
        );
    }

    #[test]
    fn round_trips_through_toml_serialization() {
        let manifest = Manifest::parse(PLAN_EXAMPLE).unwrap();
        let text = toml::to_string(&manifest).unwrap();
        let reparsed = Manifest::parse(&text).unwrap();
        assert_eq!(reparsed.environment_names(), manifest.environment_names());
        assert_eq!(reparsed.secrets.len(), manifest.secrets.len());
        assert_eq!(reparsed.vars, manifest.vars);
        // The §12 spellings survive serialization.
        assert!(text.contains("env_var = \"DB_PASSWORD\""));
        assert!(text.contains("max_tier = 1"));
        assert!(
            text.contains("mode = \"api-key\""),
            "kebab-case mode pinned: {text}"
        );
    }

    // -----------------------------------------------------------------
    // [exec] env_passthrough (plan/06 §7 — the manifest-configurable half
    // of the exec broker's deny-by-default base-env allowlist)
    // -----------------------------------------------------------------

    #[test]
    fn exec_env_passthrough_parses_and_round_trips_including_globs() {
        let text = r#"
schema = 1
[exec]
env_passthrough = ["NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "npm_*", "HTTP_PROXY"]
"#;
        let manifest = Manifest::parse(text).unwrap();
        let pt = manifest.env_passthrough();
        assert_eq!(
            pt.display_entries(),
            vec!["NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "npm_*", "HTTP_PROXY"]
        );

        // Exact entries match exactly; the glob matches by prefix only.
        assert!(pt.matches("NODE_OPTIONS"));
        assert!(pt.matches("HTTP_PROXY"));
        assert!(pt.matches("npm_config_registry"));
        assert!(pt.matches("npm_lifecycle_event"));
        assert!(!pt.matches("NODE_OPTION")); // not a prefix rule
        assert!(!pt.matches("NODE_OPTIONS_EXTRA"));
        assert!(!pt.matches("NPM_TOKEN")); // case-sensitive: npm_* != NPM_*
        assert!(!pt.matches("HTTPS_PROXY")); // not listed

        // Round-trip through serialize -> parse, glob spelling intact.
        let rendered = toml::to_string(&manifest).unwrap();
        assert!(
            rendered.contains("env_passthrough = "),
            "underscore spelling must survive: {rendered}"
        );
        assert!(rendered.contains("\"npm_*\""), "glob survives: {rendered}");
        let reparsed = Manifest::parse(&rendered).unwrap();
        assert_eq!(
            reparsed.env_passthrough().display_entries(),
            pt.display_entries()
        );
    }

    #[test]
    fn absent_or_empty_exec_block_yields_empty_passthrough() {
        // Absent [exec] entirely — the frozen base-only posture, no regression.
        let none = Manifest::parse("schema = 1\n").unwrap();
        assert!(none.exec.is_none());
        assert!(none.env_passthrough().is_empty());
        assert!(!none.env_passthrough().matches("NODE_OPTIONS"));

        // Present but empty.
        let empty = Manifest::parse("schema = 1\n[exec]\nenv_passthrough = []\n").unwrap();
        assert!(empty.env_passthrough().is_empty());
        assert!(!empty.env_passthrough().matches("anything"));
    }

    #[test]
    fn invalid_passthrough_entries_are_rejected_at_parse() {
        let bad = [
            // Empty / whitespace / bad charset.
            "",
            " ",
            "has space",
            "1LEADING_DIGIT",
            "has-dash",
            // '=' would smuggle a VALUE through a names-only list.
            "NODE_OPTIONS=--max-old-space-size=4096",
            "=VALUE",
            // NUL truncates the broker's C string.
            "NUL\0NAME",
            // A bare '*' (or a near-bare one) would disable deny-by-default.
            "*",
            "A*",
            // Interior/multiple globs are not a supported form.
            "np*m",
            "npm**",
            "*_TOKEN",
            // Security-relevant scrubs the manifest must never remove.
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_*",
            "LD_*",
            "SSH_AUTH_SOCK",
            "ENVHOLSTER_SOCKET",
            "ENVHOLSTER_*",
            // Globs that would STRADDLE a forbidden prefix.
            "DY*",
            "SSH_*",
            "ENV*",
        ];
        for entry in bad {
            let text = format!(
                "schema = 1\n[exec]\nenv_passthrough = [{}]\n",
                toml::Value::String(entry.to_owned())
            );
            let got = Manifest::parse(&text);
            assert!(
                got.is_err(),
                "entry {entry:?} must be rejected at parse, got {got:?}"
            );
        }

        // ...and the accepted forms still parse (the rejections above are not
        // over-broad).
        for entry in [
            "NODE_OPTIONS",
            "npm_*",
            "HTTPS_PROXY",
            "_UNDERSCORE_LEAD",
            "no_", // shortest legal glob prefix is 2 chars, this is exact
            "np*",
        ] {
            let text = format!(
                "schema = 1\n[exec]\nenv_passthrough = [{}]\n",
                toml::Value::String(entry.to_owned())
            );
            assert!(
                Manifest::parse(&text).is_ok(),
                "entry {entry:?} must be accepted"
            );
        }
    }

    #[test]
    fn passthrough_schema_is_names_only_no_value_form() {
        // A table form (`NODE_OPTIONS = "..."`) is a type error, not a silent
        // value injection: the manifest can NEVER set an exec env value.
        let table_form = "schema = 1\n[exec.env_passthrough]\nNODE_OPTIONS = \"--inspect\"\n";
        assert!(Manifest::parse(table_form).is_err());

        // Unknown keys under [exec] are refused (deny_unknown_fields), so a
        // future `env_set = {...}` cannot be smuggled past an older build.
        let unknown = "schema = 1\n[exec]\nenv_set = { A = \"b\" }\n";
        assert!(Manifest::parse(unknown).is_err());
    }

    #[test]
    fn newer_schema_is_refused_with_migration_message() {
        assert!(matches!(
            Manifest::parse("schema = 2"),
            Err(ManifestError::UnsupportedSchema {
                found: 2,
                supported: 1
            })
        ));
    }

    #[test]
    fn overlapping_secret_envs_are_rejected() {
        let overlapping = r#"
schema = 1
[environments]
names = ["dev", "prod"]
[[secret]]
name = "K"
envs = ["dev", "prod"]
[[secret]]
name = "K"
envs = ["prod"]
"#;
        assert!(matches!(
            Manifest::parse(overlapping),
            Err(ManifestError::OverlappingSecretEnvs { name, env }) if name == "K" && env == "prod"
        ));

        // A wildcard block overlaps any other block for the same name.
        let wildcard_overlap = r#"
schema = 1
[environments]
names = ["dev"]
[[secret]]
name = "K"
[[secret]]
name = "K"
envs = ["dev"]
"#;
        assert!(matches!(
            Manifest::parse(wildcard_overlap),
            Err(ManifestError::OverlappingSecretEnvs { .. })
        ));
    }

    #[test]
    fn structural_validation_errors() {
        // Undeclared env in [envs.X].
        assert!(matches!(
            Manifest::parse("schema = 1\n[envs.prod.vars]\nX = \"1\"\n"),
            Err(ManifestError::UndeclaredEnvironment { name }) if name == "prod"
        ));
        // base is implicit.
        assert!(matches!(
            Manifest::parse("schema = 1\n[environments]\nnames = [\"base\"]\n"),
            Err(ManifestError::ExplicitBase)
        ));
        // Bad env charset.
        assert!(matches!(
            Manifest::parse("schema = 1\n[environments]\nnames = [\"Prod\"]\n"),
            Err(ManifestError::InvalidEnvName { .. })
        ));
        // Duplicate env.
        assert!(matches!(
            Manifest::parse("schema = 1\n[environments]\nnames = [\"dev\", \"dev\"]\n"),
            Err(ManifestError::DuplicateEnvironment { .. })
        ));
        // Bad tier.
        assert!(matches!(
            Manifest::parse("schema = 1\n[[secret]]\nname = \"K\"\ntier = 4\n"),
            Err(ManifestError::InvalidTier { tier: 4, .. })
        ));
        // Bad agent ceiling.
        assert!(matches!(
            Manifest::parse("schema = 1\n[agents.claude]\nmax_tier = 9\n"),
            Err(ManifestError::InvalidAgentTier { tier: 9, .. })
        ));
        // Unknown top-level key (typo protection).
        assert!(matches!(
            Manifest::parse("schema = 1\n[secrets]\nname = \"K\"\n"),
            Err(ManifestError::Toml(_))
        ));
    }

    #[test]
    fn local_override_is_vars_only_d10() {
        let ok = LocalOverride::parse("[vars]\nLOG_LEVEL = \"debug\"\n").unwrap();
        assert_eq!(ok.vars["LOG_LEVEL"], "debug");
        assert!(LocalOverride::parse("").unwrap().vars.is_empty());

        // A [[secret]] block — or ANY non-vars key — is refused with D10.
        assert!(matches!(
            LocalOverride::parse("[[secret]]\nname = \"K\"\nvalue = \"hunter2\"\n"),
            Err(ManifestError::LocalNotVarsOnly { key }) if key == "secret"
        ));
        assert!(matches!(
            LocalOverride::parse("[vars]\nA = \"1\"\n[project]\nname = \"x\"\n"),
            Err(ManifestError::LocalNotVarsOnly { key }) if key == "project"
        ));
        // Non-string var values are refused (vars are plain strings).
        assert!(matches!(
            LocalOverride::parse("[vars]\nA = 1\n"),
            Err(ManifestError::Toml(_))
        ));
    }

    #[test]
    fn precedence_is_base_env_local() {
        let manifest = Manifest::parse(
            r#"
schema = 1
[environments]
names = ["prod"]
[vars]
A = "base"
B = "base"
C = "base"
[envs.prod.vars]
B = "prod"
C = "prod"
"#,
        )
        .unwrap();
        let local = LocalOverride::parse("[vars]\nC = \"local\"\n").unwrap();
        let resolved = manifest
            .resolve_vars(Some(&env("prod")), Some(&local))
            .unwrap();
        assert_eq!(resolved["A"], VarValue::Plain("base".to_owned()));
        assert_eq!(resolved["B"], VarValue::Plain("prod".to_owned()));
        assert_eq!(resolved["C"], VarValue::Plain("local".to_owned()));

        // Without the env selected, only base + local apply.
        let resolved = manifest.resolve_vars(None, Some(&local)).unwrap();
        assert_eq!(resolved["B"], VarValue::Plain("base".to_owned()));
        assert_eq!(resolved["C"], VarValue::Plain("local".to_owned()));
    }

    #[test]
    fn interpolation_resolves_vars_and_surfaces_composites() {
        let manifest = Manifest::parse(PLAN_EXAMPLE).unwrap();
        let resolved = manifest.resolve_vars(Some(&env("prod")), None).unwrap();
        // DATABASE_URL references DB_HOST (var → substituted) and
        // DB_PASSWORD (secret → composite, left verbatim).
        match &resolved["DATABASE_URL"] {
            VarValue::Composite {
                template,
                secret_refs,
            } => {
                assert_eq!(
                    template,
                    "postgres://app:${secret:DB_PASSWORD}@db.prod.internal/acme"
                );
                assert_eq!(secret_refs.iter().collect::<Vec<_>>(), vec!["DB_PASSWORD"]);
            }
            other => panic!("expected composite, got {other:?}"),
        }
        assert_eq!(resolved["LOG_LEVEL"], VarValue::Plain("info".to_owned()));
    }

    #[test]
    fn interpolation_hard_errors() {
        // Cycle.
        let cyclic = Manifest::parse("schema = 1\n[vars]\nA = \"${B}\"\nB = \"${A}\"\n").unwrap();
        assert!(matches!(
            cyclic.resolve_vars(None, None),
            Err(ManifestError::InterpolationCycle { .. })
        ));
        // Self-cycle.
        let self_cycle = Manifest::parse("schema = 1\n[vars]\nA = \"${A}\"\n").unwrap();
        assert!(matches!(
            self_cycle.resolve_vars(None, None),
            Err(ManifestError::InterpolationCycle { name }) if name == "A"
        ));
        // Unknown name.
        let unknown = Manifest::parse("schema = 1\n[vars]\nA = \"${NOPE}\"\n").unwrap();
        assert!(matches!(
            unknown.resolve_vars(None, None),
            Err(ManifestError::UnknownReference { reference, .. }) if reference == "NOPE"
        ));
        // Disambiguators are honored: var: on a secret name fails.
        let disambiguated =
            Manifest::parse("schema = 1\n[vars]\nA = \"${var:S}\"\n[[secret]]\nname = \"S\"\n")
                .unwrap();
        assert!(matches!(
            disambiguated.resolve_vars(None, None),
            Err(ManifestError::UnknownReference { .. })
        ));
        // Malformed.
        let unclosed = Manifest::parse("schema = 1\n[vars]\nA = \"${B\"\n").unwrap();
        assert!(matches!(
            unclosed.resolve_vars(None, None),
            Err(ManifestError::MalformedReference { .. })
        ));
    }

    /// One unknown reference must not flatten the rest of `[vars]`: the
    /// lenient per-var pass keeps a valid `${secret:...}` composite as a
    /// composite (so delivery still materializes the secret) and only the
    /// bad var falls back to its raw text.
    #[test]
    fn lenient_resolution_preserves_valid_composites_next_to_a_bad_reference() {
        let manifest = Manifest::parse(
            "schema = 1\n\
             [vars]\n\
             DB_URL = \"postgres://app:${secret:DB_PASSWORD}@db/app\"\n\
             BAD = \"${NOPE}\"\n\
             DEPENDS_ON_BAD = \"x-${BAD}\"\n\
             LOG_LEVEL = \"info\"\n\
             [[secret]]\n\
             name = \"DB_PASSWORD\"\n",
        )
        .unwrap();
        assert!(matches!(
            manifest.resolve_vars(None, None),
            Err(ManifestError::UnknownReference { .. })
        ));
        let resolved = manifest.resolve_vars_lenient(None, None);
        match &resolved["DB_URL"] {
            VarValue::Composite {
                template,
                secret_refs,
            } => {
                assert_eq!(template, "postgres://app:${secret:DB_PASSWORD}@db/app");
                assert_eq!(secret_refs.iter().collect::<Vec<_>>(), vec!["DB_PASSWORD"]);
            }
            other => panic!("DB_URL must stay a composite, got {other:?}"),
        }
        assert_eq!(resolved["BAD"], VarValue::Plain("${NOPE}".to_owned()));
        assert_eq!(
            resolved["DEPENDS_ON_BAD"],
            VarValue::Plain("x-${BAD}".to_owned()),
            "a var depending on the bad one falls back to its own raw text"
        );
        assert_eq!(resolved["LOG_LEVEL"], VarValue::Plain("info".to_owned()));
    }

    #[test]
    fn composite_ness_propagates_through_var_references() {
        let manifest = Manifest::parse(
            r#"
schema = 1
[vars]
URL = "${secret:TOKEN}@host"
WRAPPED = "prefix ${URL} suffix"
[[secret]]
name = "TOKEN"
"#,
        )
        .unwrap();
        let resolved = manifest.resolve_vars(None, None).unwrap();
        match &resolved["WRAPPED"] {
            VarValue::Composite {
                template,
                secret_refs,
            } => {
                assert_eq!(template, "prefix ${secret:TOKEN}@host suffix");
                assert!(secret_refs.contains("TOKEN"));
            }
            other => panic!("expected composite, got {other:?}"),
        }
    }

    fn meta(name: &str, env_name: &str, tier: Tier, mode: SecretMode) -> SecretMeta {
        SecretMeta {
            name: name.to_owned(),
            env: env(env_name),
            tier,
            mode,
            guarantee: Guarantee::Unassigned,
            needs_rotation: false,
            rotated_at: 0,
            rotate_after: None,
        }
    }

    #[test]
    fn check_flags_divergences_and_vault_stays_authoritative() {
        let manifest = Manifest::parse(PLAN_EXAMPLE).unwrap();

        // In lockstep: dev tier 1, prod tier 3 — no findings for these.
        let list = vec![
            meta("DB_PASSWORD", "dev", Tier::Ambient, SecretMode::ApiKey),
            meta("DB_PASSWORD", "prod", Tier::Critical, SecretMode::ApiKey),
        ];
        assert!(manifest.check_against_vault(&list).is_empty());

        // A vault record the manifest never declared.
        let undeclared = vec![meta("ROGUE", "dev", Tier::Ambient, SecretMode::Generic)];
        assert!(matches!(
            &manifest.check_against_vault(&undeclared)[..],
            [CheckFinding::ValueButUndeclared { name, .. }, ..] if name == "ROGUE"
        ));

        // The attack the P2 rule exists for: manifest says tier 1, vault
        // says tier 3 — flagged as an attempted LOWERING; effective tier
        // stays at the vault's 3.
        let lowered = vec![meta(
            "DB_PASSWORD",
            "prod",
            Tier::Critical,
            SecretMode::ApiKey,
        )];
        let mut evil = manifest.clone();
        for decl in &mut evil.secrets {
            if decl.envs == vec!["prod".to_owned()] {
                decl.tier = Some(1);
            }
        }
        let findings = evil.check_against_vault(&lowered);
        assert!(findings.iter().any(|f| matches!(
            f,
            CheckFinding::TierDivergence {
                attempted_lowering: true,
                manifest: 1,
                vault: Tier::Critical,
                ..
            }
        )));
        assert_eq!(
            effective_tier(Tier::Critical, Some(Tier::Ambient)),
            Tier::Critical,
            "the manifest can never lower the vault tier"
        );
        assert_eq!(
            effective_tier(Tier::Ambient, Some(Tier::Critical)),
            Tier::Critical,
            "the manifest may raise the effective tier"
        );
        assert_eq!(effective_tier(Tier::Sensitive, None), Tier::Sensitive);

        // Mode divergence.
        let flipped = vec![meta(
            "DB_PASSWORD",
            "dev",
            Tier::Ambient,
            SecretMode::EnvVar,
        )];
        assert!(manifest
            .check_against_vault(&flipped)
            .iter()
            .any(|f| matches!(f, CheckFinding::ModeDivergence { .. })));

        // Declared-but-no-value (project scope only; github_ssh is
        // user-scoped and never expected in the project vault).
        let missing = manifest.check_against_vault(&[]);
        assert!(missing.iter().any(|f| matches!(
            f,
            CheckFinding::DeclaredButNoValue { name, env } if name == "DB_PASSWORD" && env == "dev"
        )));
        assert!(
            !missing
                .iter()
                .any(|f| matches!(f, CheckFinding::DeclaredButNoValue { name, .. } if name == "github_ssh")),
            "user-scoped secrets are satisfied from user vaults (c38)"
        );

        // A base-cell value satisfies any env (secret resolution falls back
        // to base).
        let base_backed = vec![meta(
            "DB_PASSWORD",
            "base",
            Tier::Ambient,
            SecretMode::ApiKey,
        )];
        let findings = manifest.check_against_vault(&base_backed);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f, CheckFinding::DeclaredButNoValue { .. })),
            "{findings:?}"
        );
    }

    /// Two secrets delivered under one name in a shared environment are
    /// refused; disjoint environments may reuse an alias.
    #[test]
    fn colliding_delivery_names_are_refused_in_strict_mode() {
        let same_alias = "schema = 1\n\n[environments]\nnames = [\"prod\", \"dev\"]\n\n\
             [[secret]]\nname = \"B\"\nenv_var = \"OUT\"\n\n\
             [[secret]]\nname = \"A\"\nenv_var = \"OUT\"\n";
        assert!(matches!(
            Manifest::parse(same_alias),
            Err(ManifestError::DeliveryNameCollision { ref env_var, .. }) if env_var == "OUT"
        ));
        let alias_hits_a_name = "schema = 1\n\n\
             [[secret]]\nname = \"A\"\n\n\
             [[secret]]\nname = \"B\"\nenv_var = \"A\"\n";
        assert!(matches!(
            Manifest::parse(alias_hits_a_name),
            Err(ManifestError::DeliveryNameCollision { ref env_var, .. }) if env_var == "A"
        ));
        let disjoint = "schema = 1\n\n[environments]\nnames = [\"prod\", \"dev\"]\n\n\
             [[secret]]\nname = \"A\"\nenvs = [\"prod\"]\nenv_var = \"OUT\"\n\n\
             [[secret]]\nname = \"B\"\nenvs = [\"dev\"]\nenv_var = \"OUT\"\n";
        assert!(Manifest::parse(disjoint).is_ok());
        // prod inherits base's B, so a prod secret aliased to B collides.
        let via_fallback = "schema = 1\n\n[environments]\nnames = [\"prod\"]\n\n\
             [[secret]]\nname = \"B\"\nenvs = [\"base\"]\n\n\
             [[secret]]\nname = \"A\"\nenvs = [\"prod\"]\nenv_var = \"B\"\n";
        assert!(matches!(
            Manifest::parse(via_fallback),
            Err(ManifestError::DeliveryNameCollision { ref env_var, .. }) if env_var == "B"
        ));
        // A base alias is inherited by an env with no declaration of its own.
        let inherited = Manifest::parse(
            "schema = 1\n\n[environments]\nnames = [\"prod\"]\n\n\
             [[secret]]\nname = \"A\"\nenvs = [\"base\"]\nenv_var = \"OUT\"\n",
        )
        .unwrap();
        assert_eq!(
            inherited.delivery_name("A", &EnvName::parse("prod").unwrap()),
            "OUT"
        );
        assert_eq!(inherited.delivery_name("A", &EnvName::base()), "OUT");
        assert_eq!(inherited.delivery_name("Z", &EnvName::base()), "Z");
    }
}
