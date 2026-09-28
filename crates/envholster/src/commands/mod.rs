//! Command implementations for the single-binary CLI (PLAN.md).

pub mod doctor;
pub mod exportcmd;
pub mod identity;
pub mod importcmd;
pub mod init;
pub mod merge_driver;
pub mod recipient;
pub mod recovery;
pub mod run;
pub mod secret;
pub mod status;

use envholster_core::{
    CellId, EnvName, Manifest, ManifestError, RecipientClass, RecipientEntry, Tier, Vault,
};

use crate::context::Session;
use crate::errors::{CliError, EXIT_LOCKED};

/// A typo'd `--env` must refuse, never silently deliver the base layers to a
/// command that expected another environment's credentials. The hint names
/// the environments that ARE declared, so the next attempt is the right one.
pub(crate) fn undeclared_env_error(error: ManifestError, manifest: &Manifest) -> CliError {
    let mut declared = vec![envholster_core::constants::BASE_ENV.to_owned()];
    declared.extend(manifest.environment_names().iter().map(|s| (*s).to_owned()));
    CliError::from(error).with_next(format!(
        "declared environments: {}; declare a new one under [envs.<name>] in envholster.toml",
        declared.join(", ")
    ))
}

/// A recipient's enrolled max tier for an env (mirror of the wrap-matrix
/// lookup; the `Enrollment` payload is public).
pub fn enrolled_max_tier(entry: &RecipientEntry, env: &EnvName) -> Option<Tier> {
    match &entry.enrollment.0 {
        envholster_core::EnvSelector::All { max_tier } => Some(*max_tier),
        envholster_core::EnvSelector::Named(map) => map.get(env).copied(),
    }
}

/// Is any hardware recipient enrolled for (env, tier)? Without one, a
/// tier-2 or tier-3 cell cannot be created (the wrap matrix has nothing to
/// wrap it to), so `set --tier 2` refuses and `import` stores at tier 1.
pub fn has_hardware_for(vault: &Vault, env: &EnvName, tier: Tier) -> bool {
    vault.recipients().iter().any(|r| {
        r.class == RecipientClass::Hardware && enrolled_max_tier(r, env).is_some_and(|m| m >= tier)
    })
}

/// Unlocks EVERY persisted cell — required before any `save`: the header
/// core (which changes on every save) is every cell's AAD, so core re-encrypts
/// every body and needs every DEK (plan/02 §3–4). On a vault with tier >= 2
/// cells this needs the hardware recipient's identity.
pub fn unlock_all_persisted(vault: &mut Vault, session: &mut Session) -> Result<(), CliError> {
    for status in vault.cells() {
        if !status.unlocked {
            session.unlock(vault, &status.id)?;
        }
    }
    Ok(())
}

/// Best-effort unlock of every existing tier-1 cell (never triggers a
/// hardware op). Returns (unlocked, still_locked) cell ids; tier >= 2 cells
/// are always reported as locked here — their unlock is a hardware op the
/// caller must request deliberately.
pub fn unlock_ambient_cells(
    vault: &mut Vault,
    session: &mut Session,
) -> (Vec<CellId>, Vec<CellId>) {
    let mut unlocked = Vec::new();
    let mut locked = Vec::new();
    for status in vault.cells() {
        if status.unlocked {
            unlocked.push(status.id);
            continue;
        }
        if status.id.tier == Tier::Ambient {
            match session.unlock(vault, &status.id) {
                Ok(()) => unlocked.push(status.id),
                Err(_) => locked.push(status.id),
            }
        } else {
            locked.push(status.id);
        }
    }
    (unlocked, locked)
}

/// Locates the cell holding `name` under the frozen resolution rule
/// (selected env, falling back to `base` — plan/02 §12), unlocking candidate
/// cells as needed. DECLARATION-AWARE: the selected environment's cells
/// are searched only when a `[[secret]]` block governs `name` there, so a
/// record that slipped in without a declaration (merge drift, a failed
/// manifest write) can never shadow the declared base value. The base cell
/// is fallback storage: it is searched whenever `name` is declared for the
/// selected env OR for base (a base value satisfies a prod-only
/// declaration, plan/02 §12). Search
/// order per env: the declared tier first (fewer needless hardware taps),
/// then tiers 1..3. Only cells that exist are touched.
pub fn find_secret_cell(
    vault: &mut Vault,
    session: &mut Session,
    manifest: &Manifest,
    name: &str,
) -> Result<CellId, CliError> {
    let base = EnvName::base();
    let declared_here = manifest.secret_decl(name, &session.env).is_some();
    let declared_base = manifest.secret_decl(name, &base).is_some();
    let mut candidate_envs: Vec<EnvName> = Vec::new();
    if declared_here {
        candidate_envs.push(session.env.clone());
    }
    if session.env != base && (declared_here || declared_base) {
        candidate_envs.push(base);
    }

    let existing: Vec<CellId> = vault.cells().into_iter().map(|c| c.id).collect();
    let mut blocked: Vec<(CellId, CliError)> = Vec::new();

    for env in &candidate_envs {
        let mut tiers: Vec<Tier> = Vec::new();
        if let Some(decl) = manifest.secret_decl(name, env) {
            if let Some(t) = decl.tier.and_then(Tier::try_from_u8) {
                tiers.push(t);
            }
        }
        for t in [Tier::Ambient, Tier::Sensitive, Tier::Critical] {
            if !tiers.contains(&t) {
                tiers.push(t);
            }
        }
        for tier in tiers {
            let cell = CellId {
                env: env.clone(),
                tier,
            };
            if !existing.contains(&cell) {
                continue;
            }
            match session.unlock(vault, &cell) {
                Ok(()) => {
                    if vault.get_secret(&cell, name).is_ok() {
                        return enforce_declared_tier(manifest, &session.env, name, cell);
                    }
                }
                Err(e) => blocked.push((cell, e)),
            }
        }
    }

    if !blocked.is_empty() {
        let cells = blocked
            .iter()
            .map(|(c, _)| format!("{}:{}", c.env.as_str(), c.tier.as_u8()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CliError::new(
            "VAULT_LOCKED",
            EXIT_LOCKED,
            format!(
                "secret {name:?} was not found in any unlockable cell, and cells [{cells}] could \
                 not be unlocked with the supplied identities ({})",
                blocked[0].1.message
            ),
            Some(
                "supply an identity that can unwrap those cells (--identity <path>, \
                 ENVHOLSTER_IDENTITY, or connect the hardware token), or run 'envholster list'"
                    .to_owned(),
            ),
        ));
    }
    Err(CliError::new(
        "SECRET_NOT_FOUND",
        crate::errors::EXIT_NOT_FOUND,
        format!(
            "secret {name:?} not found in environment {:?} (or base fallback)",
            session.env.as_str()
        ),
        Some(format!("envholster list  # or: envholster set {name}")),
    ))
}

/// The tier the selected environment declares for `name` (its own block,
/// else the base block it falls back to), if any.
pub fn declared_tier_for(manifest: &Manifest, env: &EnvName, name: &str) -> Option<Tier> {
    manifest
        .secret_decl(name, env)
        .or_else(|| manifest.secret_decl(name, &EnvName::base()))
        .and_then(|d| d.tier)
        .and_then(Tier::try_from_u8)
}

/// A record is delivered only at the strength the selected environment
/// declares: a tier-1 value stored in base must not satisfy a prod
/// declaration at tier 3 (`effective_tier`, plan/02 §12). Refusing here
/// keeps `run`, `get` and `export` on the same rule `doctor` reports.
pub fn enforce_declared_tier(
    manifest: &Manifest,
    env: &EnvName,
    name: &str,
    cell: CellId,
) -> Result<CellId, CliError> {
    if let Some(required) = declared_tier_for(manifest, env, name) {
        if cell.tier < required {
            return Err(CliError::denied(
                format!(
                    "{name} is stored at tier {} (cell {}:{}) but environment {:?} declares tier \
                     {}; a weaker value is not delivered",
                    cell.tier.as_u8(),
                    cell.env.as_str(),
                    cell.tier.as_u8(),
                    env.as_str(),
                    required.as_u8()
                ),
                Some(format!(
                    "store it at the declared tier (envholster --env {} set {name} --tier {}, \
                     which needs a hardware recipient above tier 1) or lower the [[secret]] tier \
                     in envholster.toml",
                    env.as_str(),
                    required.as_u8()
                )),
            ));
        }
    }
    Ok(cell)
}

/// Lowercase display name of a recipient class (floors, badges).
pub fn class_name(class: RecipientClass) -> &'static str {
    match class {
        RecipientClass::Hardware => "hardware",
        RecipientClass::Software => "software",
        RecipientClass::Recovery => "recovery",
    }
}

/// The refusal both dotenv doors (`run --dotenv`, `export --format dotenv`)
/// give a value no reader encodes unambiguously. `reason` is what
/// `envholster_core::dotenv::readers_disagree_reason` said about the value,
/// so the message names the actual cause.
pub fn dotenv_unencodable(name: &str, reason: &str, next: &str) -> CliError {
    CliError::denied(
        format!(
            "{name} cannot be written to a dotenv file: {reason}, and no dotenv encoding of that \
             is read the same way by every reader (Node --env-file, npm dotenv, python-dotenv, \
             Docker Compose)"
        ),
        Some(next.to_owned()),
    )
}
