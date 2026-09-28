//! `doctor` — this machine and this project, with the exact remediation per
//! finding; exit 7 when something needs fixing (PLAN.md; RECOVERY-SPEC §1).
//!
//! Findings: a recovery identity still on this machine (parked by `init`, or
//! found on a known identity path); `.gitignore` not covering `.env`; a
//! leftover `run --dotenv` file; recovery-blob drift; manifest-vs-vault
//! divergence; an `[exec]` section this version ignores; a missing git merge
//! driver; file and directory modes; memlock support.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use envholster_core::constants::{DIR_MODE_SECRET, FILE_MODE_SECRET};
use envholster_core::{
    CheckFinding, EnvName, LocalOverride, Manifest, RecipientClass, RecipientKind, Vault,
};
use zeroize::Zeroize;

use crate::commands::merge_driver::missing_merge_driver_config;
use crate::commands::recovery::{parked_identities, parked_identity_path};
use crate::commands::run::{gitignore_covers_dotenv, DOTENV_MARKER};
use crate::commands::status::recovery_badge;
use crate::commands::unlock_ambient_cells;
use crate::context::{
    config_dir, discover_project, identities_dir, identity_dir_files, now_epoch, open_vault,
    uuid_string, Session,
};
use crate::errors::{CliError, EXIT_FINDINGS, EXIT_OK};
use crate::manifestio::{load_local, load_manifest_permissive};

struct Report {
    errors: Vec<String>,
    warnings: Vec<String>,
    ok: Vec<String>,
}

impl Report {
    fn new() -> Self {
        Report {
            errors: Vec::new(),
            warnings: Vec::new(),
            ok: Vec::new(),
        }
    }
}

pub fn run(session: &mut Session) -> Result<i32, CliError> {
    let mut report = Report::new();

    // --- memlock (plan/03 §3.5) ---
    if envholster_mem::mlock_supported() {
        report
            .ok
            .push("mlock: supported (raw libc::mlock probe)".to_owned());
    } else {
        report.errors.push(
            "mlock: UNSUPPORTED — locked secret buffers cannot be created; on Linux raise \
             RLIMIT_MEMLOCK (root drop-in or CAP_IPC_LOCK; a user unit's LimitMEMLOCK= cannot \
             exceed the kernel hard limit)"
                .to_owned(),
        );
    }
    match envholster_mem::lock_budget() {
        Ok(budget) => {
            let limit = budget
                .limit_bytes
                .map(|b| format!("{b} bytes"))
                .unwrap_or_else(|| "unlimited".to_owned());
            report.ok.push(format!(
                "memlock budget: limit {limit}, page size {} (locked now: {} bytes)",
                budget.page_size, budget.locked_bytes
            ));
            if let Some(limit) = budget.limit_bytes {
                if limit <= 64 * 1024 {
                    report.warnings.push(format!(
                        "RLIMIT_MEMLOCK is only {limit} bytes (old-kernel/container default) — \
                         large vaults may fail closed with LockExhausted; raise the limit"
                    ));
                }
            }
        }
        Err(e) => report
            .errors
            .push(format!("memlock budget probe failed: {e}")),
    }

    // --- identity files at the fixed path ---
    let dir = identities_dir();
    if dir.is_dir() {
        check_mode(&mut report, &dir, DIR_MODE_SECRET, true);
        for file in identity_dir_files() {
            check_mode(&mut report, &file, FILE_MODE_SECRET, false);
        }
        report.ok.push(format!(
            "identity dir: {} ({} file(s))",
            dir.display(),
            identity_dir_files().len()
        ));
    } else {
        report.warnings.push(format!(
            "no identity dir at {} — generate one: envholster identity generate",
            dir.display()
        ));
    }

    let parked = parked_identities();

    // --- project-scoped checks ---
    match discover_project() {
        Err(_) => {
            report.warnings.push(
                "not inside an envholster project (no envholster.toml found walking up) — \
                 vault checks skipped; run 'envholster init' to create one"
                    .to_owned(),
            );
            for path in &parked {
                report.errors.push(format!(
                    "recovery identity on this machine's disk: {} — inside that project, run: \
                     envholster recovery create",
                    path.display()
                ));
            }
        }
        Ok(project) => {
            if gitignore_covers_dotenv(&project.root) {
                report.ok.push(".gitignore ignores .env".to_owned());
            } else {
                report.errors.push(format!(
                    "{}/.gitignore does not ignore .env — fix: printf '.env\\n.env.*\\n\
                     !.env.example\\n' >> .gitignore",
                    project.root.display()
                ));
            }
            // Any file in the project root that starts with the marker, not
            // just the default `.env`: `--dotenv <path>` can leave one under
            // any name.
            // ... and any target a run noted in flight and never cleared
            // (a signalled run at `--dotenv <nested path>`); a record whose
            // file is gone is dropped here.
            let root = project.root.canonicalize().unwrap_or(project.root.clone());
            let mut leftovers: std::collections::BTreeSet<PathBuf> =
                leftover_dotenv_files(&project.root)
                    .into_iter()
                    .map(|p| p.canonicalize().unwrap_or(p))
                    .collect();
            for inflight in crate::commands::run::inflight_dotenv_paths() {
                let target = inflight
                    .target
                    .canonicalize()
                    .unwrap_or(inflight.target.clone());
                if !has_dotenv_marker(&target) {
                    let _ = std::fs::remove_file(&inflight.record);
                } else if inflight.writer_alive() {
                    // Not a leftover: the run that wrote it is still going.
                    leftovers.remove(&target);
                    report.warnings.push(format!(
                        "{} is in use by a running `envholster run --dotenv` (pid {}); it goes \
                         away when that command exits",
                        target.display(),
                        inflight.pid.unwrap_or(0)
                    ));
                } else {
                    leftovers.insert(target);
                }
            }
            for leftover in leftovers {
                let line = format!(
                    "leftover `run --dotenv` file at {} (a signalled run could not delete it; it \
                     holds plaintext secrets) — fix: rm {}",
                    leftover.display(),
                    leftover.display()
                );
                // Another project's leftover is worth knowing about, but it is
                // not this project's finding.
                if leftover.starts_with(&root) {
                    report.errors.push(line);
                } else {
                    report.warnings.push(format!("(another project) {line}"));
                }
            }
            let missing = missing_merge_driver_config(&project.root);
            if missing.is_empty() {
                report
                    .ok
                    .push("git merge driver for secrets.holster is configured".to_owned());
            } else {
                report.warnings.push(format!(
                    "git merge driver for secrets.holster is not fully configured (missing: {}) \
                     — re-run 'envholster import' or apply the listed lines",
                    missing.join("; ")
                ));
            }

            let manifest = match load_manifest_permissive(&project.manifest_path) {
                Ok(manifest) => Some(manifest),
                Err(e) => {
                    report.warnings.push(format!(
                        "manifest unreadable, manifest checks skipped: {}",
                        e.message
                    ));
                    None
                }
            };
            // The strict parse `run` and `export` use: a manifest they would
            // refuse (colliding delivery names, overlapping scopes) is a
            // finding here, with the parser's own reason.
            if let Err(e) = crate::manifestio::load_manifest(&project.manifest_path) {
                report.errors.push(format!(
                    "envholster.toml is refused by run/export: {} — fix the manifest",
                    e.message
                ));
            }
            if let Some(manifest) = &manifest {
                if !manifest.env_passthrough().is_empty() {
                    report.warnings.push(
                        "`[exec] env_passthrough` has no effect in this version: `run` passes \
                         your whole shell environment through (minus DYLD_*/LD_*, the identity \
                         variables, and declared secret names); the section can be removed"
                            .to_owned(),
                    );
                }
            }

            match open_vault(&project) {
                Err(e) => report.errors.push(format!(
                    "vault {} unreadable: {} — {}",
                    project.vault_path.display(),
                    e.message,
                    e.next.unwrap_or_default()
                )),
                Ok(mut vault) => {
                    check_mode(&mut report, &project.vault_path, FILE_MODE_SECRET, false);
                    let blob = project.recovery_blob_path();
                    if blob.is_file() {
                        check_mode(&mut report, &blob, FILE_MODE_SECRET, false);
                    }
                    for badge in recovery_badge(&project, &vault) {
                        match badge.kind {
                            "recovery-blob-missing" | "recovery-blob-drift" => {
                                report.errors.push(badge.message)
                            }
                            _ => report.ok.push(badge.message),
                        }
                    }

                    // The recovery identity: parked by init, or on a known
                    // identity path (the one deliberate on-disk exemption).
                    let uuid = uuid_string(&vault.uuid());
                    let this_parked = parked_identity_path(&uuid);
                    if this_parked.is_file() {
                        report.errors.push(format!(
                            "recovery identity for this vault is on this machine's disk: {} — \
                             move it to paper or removable media: envholster recovery create",
                            this_parked.display()
                        ));
                    }
                    for path in parked.iter().filter(|p| **p != this_parked) {
                        report.warnings.push(format!(
                            "recovery identity for another vault is parked at {} — run \
                             'envholster recovery create' inside that project",
                            path.display()
                        ));
                    }
                    let recovery_public: Option<String> = vault
                        .recipients()
                        .iter()
                        .find(|r| r.class == RecipientClass::Recovery)
                        .and_then(|r| r.encoded.clone());
                    match &recovery_public {
                        None => report.errors.push(
                            "vault has no recovery recipient encoding — the vault header is \
                             damaged; restore from git"
                                .to_owned(),
                        ),
                        Some(public) => {
                            let hits = scan_for_recovery_identity(public, session);
                            if hits.is_empty() && !this_parked.is_file() {
                                report.ok.push(
                                    "recovery identity not found on this machine (offline, as \
                                     it should be)"
                                        .to_owned(),
                                );
                            }
                            for hit in hits {
                                report.errors.push(format!(
                                    "RECOVERY IDENTITY ON DISK: {} decrypts everything — move it \
                                     back to paper/removable media and delete this file; if it \
                                     may have been exposed, treat every value in the vault as \
                                     exposed and rotate them at their providers",
                                    hit.display()
                                ));
                            }
                        }
                    }

                    if let Some(manifest) = &manifest {
                        let local = load_local(&project).unwrap_or(None);
                        divergence_findings(
                            &mut report,
                            session,
                            &mut vault,
                            manifest,
                            local.as_ref(),
                        );
                    }

                    let hardware: Vec<_> = vault
                        .recipients()
                        .iter()
                        .filter(|r| r.class == RecipientClass::Hardware)
                        .collect();
                    if hardware.is_empty() {
                        report.ok.push(
                            "no hardware recipient enrolled: secrets are stored at tier 1"
                                .to_owned(),
                        );
                    }
                    for entry in hardware {
                        if let RecipientKind::Plugin { name } = &entry.kind {
                            let binary = format!("age-plugin-{}", name.as_str());
                            if find_in_path(&binary).is_none() {
                                report.errors.push(format!(
                                    "hardware recipient {} needs {binary} on PATH and it is \
                                     missing — install the plugin, then retry",
                                    entry.id.as_str()
                                ));
                            } else {
                                report.ok.push(format!("{binary}: found on PATH"));
                            }
                        }
                    }
                }
            }
        }
    }

    report.errors.extend(crate::onboarding::doctor_findings());
    report.errors.extend(crate::setup::diagnose());

    // --- render ---
    for line in &report.ok {
        println!("ok:      {line}");
    }
    for line in &report.warnings {
        println!("warning: {line}");
    }
    for line in &report.errors {
        println!("error:   {line}");
    }
    println!(
        "{} ok, {} warning(s), {} error(s)",
        report.ok.len(),
        report.warnings.len(),
        report.errors.len()
    );
    Ok(if report.errors.is_empty() {
        EXIT_OK
    } else {
        EXIT_FINDINGS
    })
}

/// Manifest-vs-vault: interpolation failures, declared-but-no-value,
/// value-but-undeclared, tier and mode divergence, rotation policy.
fn divergence_findings(
    report: &mut Report,
    session: &mut Session,
    vault: &mut Vault,
    manifest: &Manifest,
    local: Option<&LocalOverride>,
) {
    let mut env_names: Vec<Option<EnvName>> = vec![None];
    for name in manifest.environment_names() {
        if let Ok(env) = EnvName::parse(name) {
            env_names.push(Some(env));
        }
    }
    for env in &env_names {
        if let Err(e) = manifest.resolve_vars(env.as_ref(), local) {
            report.warnings.push(format!(
                "[vars] in env {}: {e} — `run` and `export` fall back to the raw values and leave \
                 that reference as written; fix envholster.toml",
                env.as_ref().map(|e| e.as_str()).unwrap_or("base")
            ));
        }
    }

    let (_, locked) = unlock_ambient_cells(vault, session);
    if !locked.is_empty() {
        let cells: Vec<String> = locked
            .iter()
            .map(|c| format!("{}:{}", c.env.as_str(), c.tier.as_u8()))
            .collect();
        report.warnings.push(format!(
            "cells [{}] are locked (tier >= 2 needs the hardware identity); their records were \
             not checked",
            cells.join(", ")
        ));
    }
    let vault_list = vault.list();
    let mut divergences = 0usize;
    for finding in manifest.check_against_vault(&vault_list) {
        divergences += 1;
        match finding {
            CheckFinding::DeclaredButNoValue { name, env } => {
                if locked.iter().any(|c| c.env.as_str() == env) {
                    report.warnings.push(format!(
                        "declared {name} (env {env}) has no visible value — it may live in a \
                         locked cell"
                    ));
                } else {
                    report.errors.push(format!(
                        "declared-but-no-value: {name} (env {env}) — set it: envholster --env \
                         {env} set {name}"
                    ));
                }
            }
            // An error, not a note: run, export and get deliver declared
            // secrets only, so this value reaches nothing until it is
            // declared or removed.
            CheckFinding::ValueButUndeclared { name, env } => report.errors.push(format!(
                "value-but-undeclared: {name} (env {}) is stored but not delivered by run, \
                 export or get — declare it in envholster.toml [[secret]] (any 'envholster \
                 set' does) or remove it: envholster --env {} rm {name}",
                env.as_str(),
                env.as_str()
            )),
            CheckFinding::TierDivergence {
                name,
                env,
                vault: vault_tier,
                manifest: manifest_tier,
                ..
            } => {
                // A locked cell in that env may hold the real winner (a
                // hardware-tier override this run cannot open); the visible
                // base record is then not what would be delivered, so the
                // comparison is unverified, not a divergence.
                if locked.iter().any(|c| c.env == env) {
                    report.warnings.push(format!(
                        "unverified: {name} in environment {} declares tier {manifest_tier} and a \
                         locked cell there may hold its value; the visible base record is tier {} \
                         — re-run doctor with the identity that opens {}:{}",
                        env.as_str(),
                        vault_tier.as_u8(),
                        env.as_str(),
                        manifest_tier
                    ));
                } else if manifest_tier > vault_tier.as_u8() {
                    // The stored value is WEAKER than the env declares: run,
                    // get and export refuse it, so this is an error with the
                    // two ways out.
                    report.errors.push(format!(
                        "tier divergence: {name} is stored at tier {} but environment {} declares \
                         tier {manifest_tier} — not delivered there; store it at tier {manifest_tier} \
                         (envholster --env {} set {name} --tier {manifest_tier}, needs a hardware \
                         recipient) or lower the [[secret]] tier in envholster.toml",
                        vault_tier.as_u8(),
                        env.as_str(),
                        env.as_str()
                    ));
                } else {
                    report.warnings.push(format!(
                        "tier divergence: {name} (env {}) vault={} manifest={manifest_tier} — the \
                         stored value is stronger than declared; raise the [[secret]] tier in \
                         envholster.toml to match",
                        env.as_str(),
                        vault_tier.as_u8()
                    ));
                }
            }
            CheckFinding::ModeDivergence {
                name,
                env,
                vault: vault_mode,
                manifest: manifest_mode,
            } if locked.iter().any(|c| c.env == env) => report.warnings.push(format!(
                "unverified: {name} in environment {} may have its value in a locked cell; the \
                 visible record's mode ({}) was not compared against the declared {}",
                env.as_str(),
                vault_mode.kebab_name(),
                manifest_mode.kebab_name()
            )),
            CheckFinding::ModeDivergence {
                name,
                env,
                vault: vault_mode,
                manifest: manifest_mode,
            } => report.warnings.push(format!(
                "mode divergence: {name} (env {}) vault={} manifest={} — the vault is \
                 authoritative; fix envholster.toml",
                env.as_str(),
                vault_mode.kebab_name(),
                manifest_mode.kebab_name()
            )),
        }
    }
    if divergences == 0 {
        report
            .ok
            .push("manifest and vault agree for every checkable cell".to_owned());
    }

    let now = now_epoch();
    for meta in &vault_list {
        if meta
            .rotate_after
            .is_some_and(|after| meta.rotated_at.saturating_add(after) < now)
        {
            report.warnings.push(format!(
                "rotate-after overdue: {} ({}:{}) — set a new value: envholster set {}",
                meta.name,
                meta.env.as_str(),
                meta.tier.as_u8(),
                meta.name
            ));
        }
        if meta.needs_rotation {
            report.warnings.push(format!(
                "needs-value-rotation: {} ({}:{}) — set a new value: envholster set {}",
                meta.name,
                meta.env.as_str(),
                meta.tier.as_u8(),
                meta.name
            ));
        }
    }
}

/// Regular files directly under `root` whose first line is the `--dotenv`
/// marker, sorted. Only the first line is read, so a large unrelated file
/// costs nothing.
fn leftover_dotenv_files(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| has_dotenv_marker(p))
        .collect();
    found.sort();
    found
}

/// Only the first line is read, so a large unrelated file costs nothing.
fn has_dotenv_marker(path: &Path) -> bool {
    use std::io::{BufRead, BufReader};
    std::fs::File::open(path)
        .ok()
        .and_then(|f| BufReader::new(f).lines().next())
        .and_then(Result::ok)
        .is_some_and(|line| line == DOTENV_MARKER)
}

fn check_mode(report: &mut Report, path: &Path, want: u32, is_dir: bool) {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode != want {
                report.errors.push(format!(
                    "{} has mode {mode:o}, want {want:o} — fix: chmod {want:o} {}",
                    path.display(),
                    path.display()
                ));
            } else if is_dir {
                report.ok.push(format!("{} mode {want:o}", path.display()));
            }
        }
        Err(e) => report
            .errors
            .push(format!("{} not inspectable: {e}", path.display())),
    }
}

/// Known identity paths (RECOVERY-SPEC §1): the fixed identity dir, the
/// config dir itself, `~/.age`, and any explicitly supplied identity file.
/// Flags every file whose X25519 secret matches the recovery recipient.
fn scan_for_recovery_identity(recovery_public: &str, session: &Session) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = identity_dir_files();
    if let Ok(entries) = std::fs::read_dir(config_dir()) {
        candidates.extend(entries.flatten().map(|e| e.path()).filter(|p| p.is_file()));
    }
    if let Ok(home) = std::env::var("HOME") {
        if let Ok(entries) = std::fs::read_dir(Path::new(&home).join(".age")) {
            candidates.extend(entries.flatten().map(|e| e.path()).filter(|p| p.is_file()));
        }
    }
    if let Some(flag) = &session.identity_flag {
        candidates.push(flag.clone());
    }
    if let Ok(path) = std::env::var(crate::context::ENVVAR_IDENTITY_FILE) {
        if !path.is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }

    let mut hits = Vec::new();
    for path in candidates {
        if let Ok(mut text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let line = line.trim();
                if !line.to_ascii_uppercase().starts_with("AGE-SECRET-KEY-1") {
                    continue;
                }
                if let Ok(identity) = line.parse::<age::x25519::Identity>() {
                    if identity.to_public().to_string() == recovery_public {
                        hits.push(path.clone());
                        break;
                    }
                }
            }
            text.zeroize();
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use envholster_core::constants::VAULT_FILENAME;
    use envholster_core::{
        CellId, Enrollment, EnvName, EnvSelector, Guarantee, Identity, Manifest, RecipientClass,
        RecipientEntry, SecretMode, SecretRecord, Tier, Vault, WrapContext,
    };
    use envholster_mem::SecretBytes;

    use super::*;

    fn session_with(identities: Vec<Identity>, env: &str) -> Session {
        Session::with_identities(EnvName::parse(env).unwrap(), identities)
    }

    fn record(value: &[u8]) -> SecretRecord {
        SecretRecord {
            value: SecretBytes::try_from_slice(value).unwrap(),
            mode: SecretMode::EnvVar,
            guarantee: Guarantee::Unassigned,
            created_at: 1,
            updated_at: 1,
            rotated_at: 1,
            rotate_after: None,
            needs_rotation: false,
            metadata: BTreeMap::new(),
        }
    }

    /// A prod cell this run cannot open may hold the real override: the
    /// visible base record must not be reported as a tier divergence, only
    /// as unverified.
    #[test]
    fn locked_selected_env_cell_makes_the_fallback_comparison_unverified() {
        let dir = std::env::temp_dir().join(format!(
            "envholster-doctor-locked-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let vault_path = dir.join(VAULT_FILENAME);

        let recovery = age::x25519::Identity::generate();
        let alice = age::x25519::Identity::generate();
        let mallory = age::x25519::Identity::generate();
        let named = |env: &str| {
            let mut map = BTreeMap::new();
            map.insert(EnvName::parse(env).unwrap(), Tier::Ambient);
            Enrollment(EnvSelector::Named(map))
        };
        let recipients = vec![
            RecipientEntry::from_encoded(
                &recovery.to_public().to_string(),
                RecipientClass::Recovery,
                "recovery".to_owned(),
                Enrollment(EnvSelector::All {
                    max_tier: Tier::Critical,
                }),
            )
            .unwrap(),
            RecipientEntry::from_encoded(
                &alice.to_public().to_string(),
                RecipientClass::Software,
                "alice-base".to_owned(),
                named("base"),
            )
            .unwrap(),
            RecipientEntry::from_encoded(
                &mallory.to_public().to_string(),
                RecipientClass::Software,
                "m-prod".to_owned(),
                named("prod"),
            )
            .unwrap(),
        ];
        let ctx = WrapContext::new(Arc::new(crate::context::CliUi));
        let mut vault = Vault::create(&vault_path, recipients, &ctx).unwrap();

        // Both cells written with both identities in hand.
        let mut writer = session_with(
            vec![Identity::X25519(alice.clone()), Identity::X25519(mallory)],
            "base",
        );
        for env in ["base", "prod"] {
            let cell = CellId {
                env: EnvName::parse(env).unwrap(),
                tier: Tier::Ambient,
            };
            writer.unlock(&mut vault, &cell).unwrap();
            vault
                .add_secret(&cell, "B", record(env.as_bytes()))
                .unwrap();
        }
        vault.save().unwrap();
        // The writer holds the vault lock until it is dropped.
        drop(vault);

        // Now only alice: the prod cell stays locked. Other tests in this
        // binary start child processes, and one started just before the drop
        // keeps the lock briefly, so reopen with the CLI's bounded wait.
        let mut vault =
            crate::context::open_vault_waiting(&vault_path, std::time::Duration::from_secs(5))
                .unwrap();
        let mut session = session_with(vec![Identity::X25519(alice)], "prod");
        let manifest = Manifest::parse(
            "schema = 1\n\n[environments]\nnames = [\"prod\"]\n\n\
             [[secret]]\nname = \"B\"\nenvs = [\"base\"]\ntier = 1\n\n\
             [[secret]]\nname = \"B\"\nenvs = [\"prod\"]\ntier = 3\n",
        )
        .unwrap();
        let mut report = Report::new();
        divergence_findings(&mut report, &mut session, &mut vault, &manifest, None);
        assert!(
            !report.errors.iter().any(|e| e.contains("tier divergence")),
            "a locked prod cell must not turn the base record into a divergence: {:?}",
            report.errors
        );
        assert!(
            report.warnings.iter().any(|w| w.contains("unverified: B")),
            "{:?}",
            report.warnings
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
