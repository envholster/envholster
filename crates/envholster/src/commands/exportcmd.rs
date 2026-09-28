//! `export` — the exit door (plan/07 §7.4; formats: D14 dotenv + JSON, plus
//! shell). Maximum-sensitivity op: it materializes plaintext on stdout.
//! Tier-2 and tier-3 cells are hardware-only-reachable (G-A), so the unlock
//! below IS the presence gate.
//!
//! Merge semantics (plan/02 §12): vars resolve base → env → local; secret
//! values resolve (env, tier) cells with base fallback; secrets WIN on key
//! collision; `${...}` composites materialize here (their delivery is G5 by
//! definition — the string must exist).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use envholster_core::{CellId, EnvName, SecretMode, Tier, Vault};

use crate::context::{discover_project, open_vault, uuid_string, Session};
use crate::errors::{json_string, CliError};
use crate::manifestio::{load_local, load_manifest};
use crate::materialize::materialize;
use crate::ExportFormat;

struct SecretEntry {
    /// Cell the value came from (env fallback means this may be base).
    cell: CellId,
    name: String,
    value: String,
    mode: SecretMode,
    guarantee: envholster_core::Guarantee,
    needs_rotation: bool,
    created_at: i64,
    updated_at: i64,
    rotated_at: i64,
    rotate_after: Option<i64>,
    metadata: BTreeMap<String, String>,
}

enum Entry {
    Var(String),
    Composite {
        value: String,
        refs: BTreeSet<String>,
    },
    Secret(SecretEntry),
}

pub fn run(session: &mut Session, format: &ExportFormat) -> Result<(), CliError> {
    let project = discover_project()?;
    let manifest = load_manifest(&project.manifest_path)?;
    let local = load_local(&project)?;

    let base = EnvName::base();
    let selected = session.env.clone();
    let env_opt = if selected == base {
        None
    } else {
        Some(selected.clone())
    };

    let mut vault = open_vault(&project)?;
    let mut secrets = collect_secrets_offline(&mut vault, session, &manifest)?;
    // Only declared secrets are delivered, here as in `run` and `get`: the
    // declaration is the contract, and a record without one is a `doctor`
    // finding rather than a value that one door hands out and another does
    // not.
    secrets.retain(|name, _| {
        manifest.secret_decl(name, &selected).is_some()
            || manifest.secret_decl(name, &base).is_some()
    });
    // The tier rule applies to the WINNING record only, after the selected
    // env has overridden base — the same order `find_secret_cell` gives run
    // and get. A weaker base record that a stronger selected-env record
    // replaces must not abort the export; the record that would actually be
    // delivered must not be below what the selected env declares.
    for (name, entry) in &secrets {
        crate::commands::enforce_declared_tier(&manifest, &selected, name, entry.cell.clone())?;
    }
    let vault_meta = (vault.generation(), uuid_string(&vault.uuid()));

    // --- vars (base → env → local), then composite materialization ---
    // A single unresolvable `${X}` in [vars] (a typo, a reference to a shell
    // variable the file relied on) must not make the whole export fail: fall
    // back to the raw layers and let the lenient expander below leave that
    // one reference as written. Said once on stderr, never silently. An
    // undeclared env is different: a typo'd `--env` exporting the base
    // values as if they were that environment's must refuse.
    let vars = match manifest.resolve_vars(env_opt.as_ref(), local.as_ref()) {
        Ok(v) => v,
        Err(e @ envholster_core::ManifestError::UndeclaredEnvironment { .. }) => {
            return Err(crate::commands::undeclared_env_error(e, &manifest));
        }
        Err(e) => {
            eprintln!(
                "note: [vars] exported partly unresolved ({e}); an unresolvable ${{...}} \
                 reference is left as written"
            );
            // Per-var fallback: only the vars touched by the bad reference
            // degrade to their raw text — a valid `${secret:...}` composite
            // elsewhere still materializes below instead of exporting as a
            // literal template.
            manifest.resolve_vars_lenient(env_opt.as_ref(), local.as_ref())
        }
    };

    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    for (name, value) in vars {
        match value {
            envholster_core::VarValue::Plain(v) => {
                entries.insert(name, Entry::Var(v));
            }
            envholster_core::VarValue::Composite {
                template,
                secret_refs,
            } => {
                let value = materialize(&template, &|n: &str| {
                    secrets.get(n).map(|s| s.value.clone())
                })?;
                entries.insert(
                    name,
                    Entry::Composite {
                        value,
                        refs: secret_refs,
                    },
                );
            }
        }
    }
    // Secrets win on collision (plan/02 §12).
    for (record_name, secret) in secrets {
        let key = manifest.delivery_name(&record_name, &selected);
        entries.insert(key, Entry::Secret(secret));
    }

    // `${NAME}` expansion over the final set — the same rule `run` applies
    // (`envholster_core::expand`), so the two delivery doors agree and a file
    // exported here reads the way Next.js / Vite / dotenv-expand would have
    // read the original. Braced references only; unknown ones stay literal.
    expand_entry_references(&mut entries);

    // The same deny list `run` applies to the child's environment: export's
    // output is meant to be sourced (`--format shell` says so), so a
    // repository must not be able to hand a loader hook to the user's shell
    // through it either.
    if let Some(name) = entries
        .keys()
        .find(|k| crate::exec::is_forbidden_delivery_name(k))
    {
        return Err(CliError::denied(
            format!(
                "refusing to export {name}: loader hooks (DYLD_*, LD_*) and the envholster \
                 identity variables cannot be set from the project"
            ),
            Some(format!(
                "remove {name} from envholster.toml [vars], or from the vault: envholster rm {name}"
            )),
        ));
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match format {
        ExportFormat::Dotenv => {
            // Fail closed before writing anything: a partial file is worse
            // than none, and the value still comes out of `--format json`.
            if let Some((key, reason)) = entries.iter().find_map(|(k, e)| {
                envholster_core::dotenv::readers_disagree_reason(entry_value(e)).map(|r| (k, r))
            }) {
                return Err(crate::commands::dotenv_unencodable(
                    key,
                    reason,
                    &format!("envholster export --format json   # or: envholster get {key}"),
                ));
            }
            let mut text = String::new();
            for (key, entry) in &entries {
                envholster_core::dotenv::write_dotenv_line(&mut text, key, entry_value(entry));
            }
            out.write_all(text.as_bytes())?;
        }
        ExportFormat::Json => {
            let json = render_json(&selected, Some(&vault_meta), &entries);
            out.write_all(json.as_bytes())?;
            out.write_all(b"\n")?;
        }
        ExportFormat::Shell => {
            let mut text = String::new();
            for (key, entry) in &entries {
                if !envholster_core::dotenv::is_valid_var_name(key) {
                    eprintln!("# skipped {key:?}: not a valid shell identifier");
                    continue;
                }
                text.push_str("export ");
                text.push_str(key);
                text.push_str("='");
                text.push_str(&entry_value(entry).replace('\'', "'\\''"));
                text.push_str("'\n");
            }
            out.write_all(text.as_bytes())?;
        }
    }
    out.flush()?;
    Ok(())
}

fn entry_value(entry: &Entry) -> &str {
    match entry {
        Entry::Var(v) => v,
        Entry::Composite { value, .. } => value,
        Entry::Secret(s) => &s.value,
    }
}

fn collect_cell(
    vault: &Vault,
    cell: &CellId,
    manifest: &envholster_core::Manifest,
    selected: &EnvName,
    secrets: &mut BTreeMap<String, SecretEntry>,
) -> Result<(), CliError> {
    for meta in vault.list() {
        let id = CellId {
            env: meta.env.clone(),
            tier: meta.tier,
        };
        if &id != cell {
            continue;
        }
        // A record in the SELECTED env counts only when a declaration governs
        // the name there (an undeclared record must not override the
        // declared base value); the base cell is fallback storage and counts
        // whenever the name is declared for the selected env or for base.
        let admitted = if cell.env == EnvName::base() {
            manifest.secret_decl(&meta.name, selected).is_some()
                || manifest.secret_decl(&meta.name, &cell.env).is_some()
        } else {
            manifest.secret_decl(&meta.name, &cell.env).is_some()
        };
        if !admitted {
            // Said on stderr, so an export that exits 0 never drops a value
            // silently; `doctor` names the record and the fix.
            eprintln!(
                "not exported: {} (env {}) is stored without a declaration — envholster doctor",
                meta.name,
                cell.env.as_str()
            );
            continue;
        }
        let record = vault.get_secret(cell, &meta.name).map_err(CliError::from)?;
        let value = record
            .value
            .with_exposed(|b| std::str::from_utf8(b).map(str::to_owned))
            .map_err(|_| {
                CliError::parse(
                    format!(
                        "secret {:?} holds non-UTF-8 bytes and cannot be exported as text",
                        meta.name
                    ),
                    Some(format!(
                        "envholster get {}  # raw bytes to stdout",
                        meta.name
                    )),
                )
            })?;
        secrets.insert(
            meta.name.clone(),
            SecretEntry {
                cell: cell.clone(),
                name: meta.name.clone(),
                value,
                mode: record.mode,
                guarantee: record.guarantee,
                needs_rotation: record.needs_rotation,
                created_at: record.created_at,
                updated_at: record.updated_at,
                rotated_at: record.rotated_at,
                rotate_after: record.rotate_after,
                metadata: record.metadata.clone(),
            },
        );
    }
    Ok(())
}

/// Secret collection: base cells first, then env cells overriding, unlocking
/// each existing cell (tier >= 2 is a hardware op — the presence gate).
fn collect_secrets_offline(
    vault: &mut Vault,
    session: &mut Session,
    manifest: &envholster_core::Manifest,
) -> Result<BTreeMap<String, SecretEntry>, CliError> {
    let base = EnvName::base();
    let selected = session.env.clone();
    let mut envs_in_order = vec![base.clone()];
    if selected != base {
        envs_in_order.push(selected.clone());
    }
    let existing: Vec<CellId> = vault.cells().into_iter().map(|c| c.id).collect();
    let mut secrets: BTreeMap<String, SecretEntry> = BTreeMap::new();
    for env in &envs_in_order {
        for tier in [Tier::Ambient, Tier::Sensitive, Tier::Critical] {
            let cell = CellId {
                env: env.clone(),
                tier,
            };
            if !existing.contains(&cell) {
                continue;
            }
            session.unlock(vault, &cell)?;
            collect_cell(vault, &cell, manifest, &selected, &mut secrets)?;
        }
    }
    Ok(secrets)
}

/// Hand-written JSON (no serde outside the manifest); D14: JSON carries full
/// metadata. Keys are emitted in BTreeMap order.
fn render_json(
    env: &EnvName,
    vault_meta: Option<&(u64, String)>,
    entries: &BTreeMap<String, Entry>,
) -> String {
    let mut json = String::from("{\"entries\":{");
    let mut first = true;
    for (key, entry) in entries {
        if !first {
            json.push(',');
        }
        first = false;
        json.push_str(&json_string(key));
        json.push(':');
        match entry {
            Entry::Var(value) => {
                json.push_str("{\"kind\":\"var\",\"value\":");
                json.push_str(&json_string(value));
                json.push('}');
            }
            Entry::Composite { value, refs } => {
                // 7.2: composite delivery collapses to G5 — disclosed here.
                json.push_str(
                    "{\"delivery\":\"g5-materialized\",\"kind\":\"composite\",\"secret-refs\":[",
                );
                for (i, r) in refs.iter().enumerate() {
                    if i > 0 {
                        json.push(',');
                    }
                    json.push_str(&json_string(r));
                }
                json.push_str("],\"value\":");
                json.push_str(&json_string(value));
                json.push('}');
            }
            Entry::Secret(s) => {
                json.push_str("{\"created-at\":");
                json.push_str(&s.created_at.to_string());
                json.push_str(",\"env\":");
                json.push_str(&json_string(s.cell.env.as_str()));
                // D5: unassigned prints verbatim, never a G-number.
                json.push_str(",\"guarantee\":");
                json.push_str(&json_string(s.guarantee.kebab_name()));
                json.push_str(",\"kind\":\"secret\",\"metadata\":{");
                for (i, (k, v)) in s.metadata.iter().enumerate() {
                    if i > 0 {
                        json.push(',');
                    }
                    json.push_str(&json_string(k));
                    json.push(':');
                    json.push_str(&json_string(v));
                }
                json.push_str("},\"mode\":");
                json.push_str(&json_string(s.mode.kebab_name()));
                json.push_str(",\"name\":");
                json.push_str(&json_string(&s.name));
                json.push_str(",\"needs-rotation\":");
                json.push_str(if s.needs_rotation { "true" } else { "false" });
                if let Some(after) = s.rotate_after {
                    json.push_str(",\"rotate-after\":");
                    json.push_str(&after.to_string());
                }
                json.push_str(",\"rotated-at\":");
                json.push_str(&s.rotated_at.to_string());
                json.push_str(",\"tier\":");
                json.push_str(&s.cell.tier.as_u8().to_string());
                json.push_str(",\"updated-at\":");
                json.push_str(&s.updated_at.to_string());
                json.push_str(",\"value\":");
                json.push_str(&json_string(&s.value));
                json.push('}');
            }
        }
    }
    json.push_str("},\"env\":");
    json.push_str(&json_string(env.as_str()));
    if let Some((generation, uuid)) = vault_meta {
        json.push_str(",\"generation\":");
        json.push_str(&generation.to_string());
        json.push_str(",\"vault-uuid\":");
        json.push_str(&json_string(uuid));
    }
    json.push_str(",\"schema\":1}");
    json
}

/// Expand `${NAME}` references in every exported value against the exported
/// set itself (secrets already won their collisions). Values without a
/// reference are untouched.
fn expand_entry_references(entries: &mut BTreeMap<String, Entry>) {
    use envholster_core::expand::{expand, has_reference};
    let raw: BTreeMap<String, String> = entries
        .iter()
        .map(|(k, e)| {
            let v = match e {
                Entry::Var(v) => v.clone(),
                Entry::Composite { value, .. } => value.clone(),
                Entry::Secret(s) => s.value.clone(),
            };
            (k.clone(), v)
        })
        .collect();
    let lookup = |n: &str| raw.get(n).cloned();
    for entry in entries.values_mut() {
        match entry {
            Entry::Var(v) if has_reference(v) => *v = expand(v, &lookup),
            Entry::Composite { value, .. } if has_reference(value) => {
                *value = expand(value, &lookup)
            }
            Entry::Secret(s) if has_reference(&s.value) => s.value = expand(&s.value, &lookup),
            _ => {}
        }
    }
}
