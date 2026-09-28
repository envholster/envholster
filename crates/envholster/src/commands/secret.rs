//! `set` / `get` / `rm` / `list` (plan/07 §7.5–7.6; c22, c27, D11, D13).
//!
//! Values only ever arrive via no-echo prompt or `--stdin` into locked
//! buffers — never argv. `list` never emits values. `set` creates or
//! updates; a new secret is tier 1 unless `--tier 2|3` names a tier a
//! hardware recipient is enrolled for.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};

use envholster_core::{CellId, EnvName, Guarantee, SecretMode, SecretRecord, Tier, Vault};

use crate::commands::{
    class_name, find_secret_cell, has_hardware_for, unlock_all_persisted, unlock_ambient_cells,
};
use crate::context::{discover_project, now_epoch, open_vault, read_secret_value, Session};
use crate::errors::CliError;
use crate::manifestio::{
    ensure_secret_decl, load_manifest, remove_secret_decl, remove_unused_wildcard_decl,
    store_manifest,
};

/// HB1 secret-name charset (plan/02 §5): `[A-Za-z0-9_.-]{1,128}`.
pub fn validate_secret_name(name: &str) -> Result<(), CliError> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 128
        && bytes
            .iter()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(CliError::parse(
            format!("invalid secret name {name:?}: use [A-Za-z0-9_.-]{{1,128}}"),
            None,
        ))
    }
}

pub fn parse_tier_arg(raw: u8) -> Result<Tier, CliError> {
    Tier::try_from_u8(raw).ok_or_else(|| {
        CliError::parse(
            format!("invalid tier {raw}: 1 = ambient, 2 = sensitive, 3 = critical"),
            Some("pass --tier 1|2|3".to_owned()),
        )
    })
}

/// The cell in the SELECTED env that already holds `name`, if any. `set`
/// never edits a base-env record from inside another env: that would change
/// every environment's value when the person meant one.
fn existing_cell_in_env(
    vault: &mut Vault,
    session: &mut Session,
    name: &str,
) -> Result<Option<CellId>, CliError> {
    let existing: Vec<CellId> = vault.cells().into_iter().map(|c| c.id).collect();
    for tier in [Tier::Ambient, Tier::Sensitive, Tier::Critical] {
        let cell = CellId {
            env: session.env.clone(),
            tier,
        };
        if !existing.contains(&cell) {
            continue;
        }
        session.unlock(vault, &cell)?;
        if vault.get_secret(&cell, name).is_ok() {
            return Ok(Some(cell));
        }
    }
    Ok(None)
}

/// `set <name> [--tier N] [--stdin]`: update the value if the secret exists
/// in this env, otherwise add it (mode env-var, tier 1 unless asked).
pub fn set(
    session: &mut Session,
    name: &str,
    tier_flag: Option<u8>,
    use_stdin: bool,
) -> Result<(), CliError> {
    validate_secret_name(name)?;
    let project = discover_project()?;
    let mut manifest = load_manifest(&project.manifest_path)?;
    let mut vault = open_vault(&project)?;

    // Every save re-encrypts every persisted cell (AAD covers the header
    // core), so all of them must be unlockable before we touch anything.
    unlock_all_persisted(&mut vault, session)?;

    if let Some(cell) = existing_cell_in_env(&mut vault, session, name)? {
        if let Some(raw) = tier_flag {
            if parse_tier_arg(raw)? != cell.tier {
                return Err(CliError::failure(
                    format!(
                        "{name} already exists at tier {} in env {}; a secret does not change \
                         tier in place",
                        cell.tier.as_u8(),
                        cell.env.as_str()
                    ),
                    Some(format!(
                        "envholster rm {name} && envholster set {name} --tier {raw}"
                    )),
                ));
            }
        }
        let value = read_secret_value(&format!("New value for {name} (no echo): "), use_stdin)?;
        vault
            .edit_secret(&cell, name, value)
            .map_err(CliError::from)?;
        vault.save().map_err(CliError::from)?;
        println!(
            "updated {name} in cell {}:{}",
            cell.env.as_str(),
            cell.tier.as_u8()
        );
        return Ok(());
    }

    let tier = match tier_flag {
        Some(raw) => parse_tier_arg(raw)?,
        None => Tier::Ambient,
    };
    if tier >= Tier::Sensitive && !has_hardware_for(&vault, &session.env, tier) {
        return Err(CliError::denied(
            format!(
                "no hardware recipient enrolled for tier {} (env {})",
                tier.as_u8(),
                session.env.as_str()
            ),
            Some(format!(
                "envholster set {name}  # tier 1; or enroll hardware first: envholster \
                 recipient add <age1yubikey1...|age1se1...> --class hardware --label <label>"
            )),
        ));
    }
    let cell = CellId {
        env: session.env.clone(),
        tier,
    };
    session.unlock(&mut vault, &cell)?;

    let value = read_secret_value(&format!("Value for {name} (no echo): "), use_stdin)?;
    let now = now_epoch();
    let mode = SecretMode::EnvVar;
    let record = SecretRecord {
        value,
        mode,
        guarantee: Guarantee::Unassigned,
        created_at: now,
        updated_at: now,
        rotated_at: now,
        rotate_after: None,
        needs_rotation: false,
        metadata: BTreeMap::new(),
    };
    vault
        .add_secret(&cell, name, record)
        .map_err(CliError::from)?;
    vault.save().map_err(CliError::from)?;

    // Vault saved (authoritative) — now the committed declaration (plan/02 §12).
    ensure_secret_decl(&mut manifest, name, &session.env, tier, mode);
    store_manifest(&project.manifest_path, &manifest)?;

    println!(
        "added {name} to cell {}:{}",
        cell.env.as_str(),
        cell.tier.as_u8()
    );
    Ok(())
}

pub fn get(session: &mut Session, name: &str) -> Result<(), CliError> {
    validate_secret_name(name)?;
    let project = discover_project()?;
    let manifest = load_manifest(&project.manifest_path)?;
    let base = EnvName::base();
    let declared = |n: &str| {
        manifest.secret_decl(n, &session.env).is_some() || manifest.secret_decl(n, &base).is_some()
    };

    // Which stored secret `run` would deliver under this name in this
    // environment: a secret whose env_var alias is this name, else the name
    // itself when it is declared. Secrets win a name collision (plan/02 §12)
    // here exactly as in `run` and `export`, and a locked cell holding the
    // name is an error, not a reason to print a plaintext copy instead.
    let canonical: Option<String> = manifest
        .secrets
        .iter()
        .map(|d| d.name.clone())
        .find(|n| declared(n) && manifest.delivery_name(n, &session.env) == name)
        .or_else(|| declared(name).then(|| name.to_owned()));
    if let Some(secret_name) = canonical {
        let mut vault = open_vault(&project)?;
        let cell = find_secret_cell(&mut vault, session, &manifest, &secret_name)?;
        let record = vault
            .get_secret(&cell, &secret_name)
            .map_err(CliError::from)?;
        // `with_exposed` returns the closure's `Result` directly (the value
        // is exposed only inside the closure, then re-sealed).
        return record.value.with_exposed(write_value_to_stdout);
    }

    // A [vars] entry is not a secret, and `get` should say so by answering,
    // WITHOUT touching the vault: vars live in the plaintext manifest, and a
    // running `run` holds the vault lock for its child's lifetime.
    if let Some(value) = manifest_var_value(session, name)? {
        return write_value_to_stdout(value.as_bytes());
    }

    // Neither declared nor a var. A record stored without a declaration is
    // not delivered by any door (run, export, get); `doctor` names it.
    Err(CliError::not_found(
        format!("{name} is not in envholster.toml — not a var, not a declared secret"),
        Some(format!(
            "envholster list   # what this project declares; envholster set {name} to add it"
        )),
    ))
}

/// Write a raw secret value to stdout (a terminating newline only when stdout is
/// a TTY). The value is NEVER logged.
fn write_value_to_stdout(value: &[u8]) -> Result<(), CliError> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(value).map_err(CliError::from)?;
    if handle.is_terminal() {
        let _ = handle.write_all(b"\n");
    }
    let _ = handle.flush();
    Ok(())
}

/// `rm <name>` removes the record from the SELECTED environment only. The
/// base fallback that `get` and `run` use for reading would make
/// `rm --env prod` delete the value every environment inherits; a name that
/// only exists in base is reported, not removed.
pub fn rm(session: &mut Session, name: &str) -> Result<(), CliError> {
    validate_secret_name(name)?;
    let project = discover_project()?;
    let mut manifest = load_manifest(&project.manifest_path)?;
    let mut vault = open_vault(&project)?;
    unlock_all_persisted(&mut vault, session)?;
    let Some(cell) = existing_cell_in_env(&mut vault, session, name)? else {
        let inherited = session.env != EnvName::base()
            && vault
                .list()
                .iter()
                .any(|m| m.name == name && m.env == EnvName::base());
        return Err(CliError::not_found(
            if inherited {
                format!(
                    "{name} is not set in environment {:?}; the value it inherits lives in base \
                     and was left alone",
                    session.env.as_str()
                )
            } else {
                format!(
                    "{name} is not set in environment {:?}",
                    session.env.as_str()
                )
            },
            Some(if inherited {
                format!("envholster --env base rm {name}   # remove it for every environment")
            } else {
                "envholster list".to_owned()
            }),
        ));
    };
    vault.remove_secret(&cell, name).map_err(CliError::from)?;
    vault.save().map_err(CliError::from)?;

    let mut manifest_changed = remove_secret_decl(&mut manifest, name, &cell.env);
    let still_stored = vault.list().iter().any(|m| m.name == name);
    manifest_changed |= remove_unused_wildcard_decl(&mut manifest, name, still_stored);
    if manifest_changed {
        store_manifest(&project.manifest_path, &manifest)?;
    }
    println!(
        "removed {name} from cell {}:{}{}",
        cell.env.as_str(),
        cell.tier.as_u8(),
        if manifest_changed {
            ""
        } else {
            " (manifest declaration covers other envs or is wildcard — left in place)"
        }
    );
    println!(
        "note: prior generations in git history still contain this value; rotate it at the \
         provider if it must die"
    );
    Ok(())
}

pub fn list(session: &mut Session) -> Result<(), CliError> {
    let project = discover_project()?;
    let manifest = load_manifest(&project.manifest_path)?;
    let mut vault = open_vault(&project)?;

    let (_unlocked, locked) = unlock_ambient_cells(&mut vault, session);
    let floors: BTreeMap<CellId, _> = vault
        .cells()
        .into_iter()
        .map(|c| (c.id.clone(), c.floor))
        .collect();

    let now = now_epoch();
    // Columns a first-time user can read. Mode and guarantee labels change no
    // behavior in this version, so they stay out of the default view.
    println!("NAME\tENV\tTIER\tKEY\tSTATUS");
    let mut visible: Vec<(String, String)> = Vec::new();
    let mut metas = vault.list();
    metas.sort_by(|a, b| (&a.env, a.tier, &a.name).cmp(&(&b.env, b.tier, &b.name)));
    for meta in &metas {
        let status = if meta.needs_rotation {
            "needs rotation"
        } else if meta
            .rotate_after
            .is_some_and(|after| meta.rotated_at.saturating_add(after) < now)
        {
            "rotation overdue"
        } else {
            "ok"
        };
        let key = floors
            .get(&CellId {
                env: meta.env.clone(),
                tier: meta.tier,
            })
            .map(|f| class_name(*f))
            .unwrap_or("-");
        println!(
            "{}\t{}\t{}\t{}\t{}",
            meta.name,
            meta.env.as_str(),
            meta.tier.as_u8(),
            key,
            status
        );
        visible.push((meta.name.clone(), meta.env.as_str().to_owned()));
    }

    // Manifest join: declared secrets whose value is invisible here (locked
    // tier >= 2 cell, other machine's user scope, or genuinely missing).
    for decl in &manifest.secrets {
        let envs: Vec<String> = if decl.envs.is_empty() {
            std::iter::once("base".to_owned())
                .chain(manifest.environment_names().iter().map(|s| (*s).to_owned()))
                .collect()
        } else {
            decl.envs.clone()
        };
        for env in envs {
            if visible.iter().any(|(n, e)| n == &decl.name && e == &env) {
                continue;
            }
            let status = if decl.scope == envholster_core::SecretScope::User {
                "declared; value comes from your user vault"
            } else {
                "declared; no value readable here (run 'envholster doctor')"
            };
            println!(
                "{}\t{}\t{}\t-\t{}",
                decl.name,
                env,
                decl.tier
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "?".to_owned()),
                status
            );
        }
    }

    if !locked.is_empty() {
        let cells: Vec<String> = locked
            .iter()
            .map(|c| format!("{}:{}", c.env.as_str(), c.tier.as_u8()))
            .collect();
        println!(
            "# locked cells not listed above: {} (tier >= 2 unlocks are a hardware op)",
            cells.join(", ")
        );
    }
    Ok(())
}

/// The resolved value of a manifest `[vars]` entry (base → selected env →
/// `envholster.local.toml`), with `${NAME}` references expanded against the
/// other vars, or `None` when `name` is not a var (it may still be a secret).
/// A composite that references a secret is reported literally — resolving
/// it would need the secret, and that is what `run`/`export` are for.
fn manifest_var_value(session: &Session, name: &str) -> Result<Option<String>, CliError> {
    let project = discover_project()?;
    let manifest = crate::manifestio::load_manifest_permissive(&project.manifest_path)?;
    let local = crate::manifestio::load_local(&project)?;
    let env_opt = if session.env.as_str() == envholster_core::constants::BASE_ENV {
        None
    } else {
        Some(session.env.clone())
    };
    let vars = match manifest.resolve_vars(env_opt.as_ref(), local.as_ref()) {
        Ok(v) => v,
        // An unresolvable reference elsewhere in [vars] must not hide THIS
        // var: fall back to the raw layers, expanded leniently below.
        Err(_) => manifest
            .layered_vars(env_opt.as_ref(), local.as_ref())
            .into_iter()
            .map(|(k, v)| (k, envholster_core::VarValue::Plain(v)))
            .collect(),
    };
    let Some(value) = vars.get(name) else {
        return Ok(None);
    };
    let raw = match value {
        envholster_core::VarValue::Plain(v) => v.clone(),
        envholster_core::VarValue::Composite { template, .. } => template.clone(),
    };
    let lookup = |n: &str| match vars.get(n) {
        Some(envholster_core::VarValue::Plain(v)) => Some(v.clone()),
        Some(envholster_core::VarValue::Composite { template, .. }) => Some(template.clone()),
        None => None,
    };
    Ok(Some(envholster_core::expand::expand(&raw, &lookup)))
}
