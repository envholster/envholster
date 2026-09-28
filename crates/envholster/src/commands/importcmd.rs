//! `import` — the dotenv entry door (plan/07 §7.4, c27/c40) plus the app's
//! non-interactive plan/apply/detect seam (docs/GUI-ONBOARDING.md §4.2).
//!
//! Every classification is confirmed — interactively line by line, or in the
//! machine mode by an explicit decisions file whose EXACT COVER the CLI
//! proves before writing anything (c40's no-silent-default survives the
//! machine mode because completeness is verified server-side, never trusted
//! from the client). The apply step is all-or-nothing: one vault save, then
//! one manifest write. Post-import cleanup (normative): delete each source
//! file / gitignore `.env*` — prompted interactively, explicit booleans in
//! the decisions file — and ALWAYS print the history-exposure warning.
//!
//! Values never leave this process on the plan path: the plan JSON carries
//! names, line numbers, and value LENGTHS only — no previews, no prefixes.
//! The decisions file coming back contains names and choices only. Values
//! move file→vault entirely inside this process and are zeroized after the
//! save, exactly like the interactive path.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use envholster_core::{
    CellId, EnvName, Guarantee, Manifest, SecretMode, SecretRecord, Tier, Vault,
};
use envholster_mem::SecretBytes;
use zeroize::{Zeroize, Zeroizing};

use crate::commands::{has_hardware_for, unlock_all_persisted};
use crate::context::{
    discover_project, now_epoch, open_vault, prompt_line, prompt_line_or_default, Project, Session,
};
use crate::errors::{json_escape_into, CliError, EXIT_FAILURE};
use crate::manifestio::{ensure_env_declared, ensure_secret_decl, load_manifest, store_manifest};
use envholster_core::dotenv::{classify, parse_dotenv, Classification, DotenvEntry, Suggestion};
use envholster_core::providers;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ImportProfile {
    Nextjs,
    Vite,
}

#[derive(Clone, Debug, Default, clap::Args)]
pub struct ImportOptions {
    /// Select the framework's file precedence; required for mode-specific files.
    #[arg(long, value_enum, conflicts_with = "map")]
    pub profile: Option<ImportProfile>,
    /// Encrypt every imported value, including suggested configuration.
    #[arg(long, conflicts_with = "apply")]
    pub encrypt_all: bool,
}

/// Every import carries this warning, including machine-readable results.
const HISTORY_WARNING: &str =
    "WARNING (history exposure): imported plaintext files remain until removed. \
     Deletion does not erase backups or git history. If any imported file was ever \
     committed or exposed, rotate its credentials at their providers.";

struct PlannedSecret {
    env: EnvName,
    /// The cell tier: what the hardware gate and the at-rest wrapping key on.
    tier: Tier,
    name: String,
    value: String,
    /// A recognized provider key: stored with mode `api-key` so a later proxy
    /// layer can key on it; `run` delivers it as a plain environment value in
    /// this version. `None` = plain `env-var` import.
    provider: Option<&'static providers::BrokeredProvider>,
}

impl Drop for PlannedSecret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl PlannedSecret {
    fn new(env: &EnvName, tier: Tier, name: String, value: String) -> Self {
        let provider = providers::recognize(&name, &value);
        PlannedSecret {
            env: env.clone(),
            tier,
            name,
            value,
            provider,
        }
    }

    fn mode(&self) -> SecretMode {
        if self.provider.is_some() {
            SecretMode::ApiKey
        } else {
            SecretMode::EnvVar
        }
    }
}

struct PlannedVar {
    env: EnvName,
    name: String,
    value: String,
}

/// `--map <file>=<env>` (repeatable).
pub fn parse_map_arg(raw: &str) -> Result<(PathBuf, EnvName), CliError> {
    // Split on the LAST `=`: an environment name cannot contain one, a path
    // can (`--map config=prod/.env.local=base`).
    let (file, env) = raw.rsplit_once('=').ok_or_else(|| {
        CliError::parse(
            format!("--map takes <file>=<env>, got {raw:?}"),
            Some("example: envholster import .env --map .env.production=prod".to_owned()),
        )
    })?;
    if file.is_empty() {
        return Err(CliError::parse(
            format!("--map {raw:?} names no file"),
            None,
        ));
    }
    let env = EnvName::parse(env).map_err(CliError::from)?;
    Ok((PathBuf::from(file), env))
}

/// The (file, env) source list: the positional file starts at the session
/// env, and a `--map` naming a file ALREADY in the list overrides that
/// file's env rather than appending a second source — `import .env --map
/// .env=prod` means ".env into prod", not ".env twice" (planned twice, every
/// entry doubled, and applied into BOTH envs). A map naming a new file
/// appends it; repeated maps for one file: last wins. Paths compare as
/// given — the app's plan seam always passes the identical spelling.
fn build_sources(
    env: &EnvName,
    path: &Path,
    maps: &[String],
) -> Result<Vec<(PathBuf, EnvName)>, CliError> {
    let mut sources: Vec<(PathBuf, EnvName)> = vec![(path.to_owned(), env.clone())];
    for raw in maps {
        let (file, env) = parse_map_arg(raw)?;
        if let Some(existing) = sources.iter_mut().find(|(f, _)| *f == file) {
            existing.1 = env;
        } else {
            sources.push((file, env));
        }
    }
    Ok(sources)
}

/// The comment-only file left in place of a deleted `.env`. `run --dotenv`
/// recognizes it by its exact content, replaces it for the child's lifetime,
/// and restores it on exit — the breadcrumb must never block the default
/// `--dotenv` path it shares a name with. A file that merely STARTS with it
/// (a tool appended a variable) is user content and is refused, because the
/// exit path restores this constant, not the bytes it replaced.
pub const ENV_BREADCRUMB: &str = "# Managed by Env Holster.\n\
    # Secrets are encrypted in secrets.holster; non-secret config is in envholster.toml.\n\
    # Run your app with:   envholster run -- <your command>\n\
    # See what is set with: envholster list\n";

/// After deleting an imported `.env`, leave a comment-only file in its place.
///
/// Tools that open `.env` themselves — the Prisma CLI, Docker Compose
/// `env_file:`, `node --env-file`, dotenv-cli — do not crash on an empty
/// file; some of them do crash, or silently fall back to nothing, on a
/// missing one. And a developer (or their teammate, or their agent) who
/// opens the project a month later and finds no `.env` has no idea where the
/// values went. The breadcrumb answers both: the file exists, it carries no
/// value, and it says how to run the app. `.env*` is gitignored by the step
/// that follows, so it never commits. Only the exact name `.env` gets one —
/// `.env.production` and friends are deleted outright.
fn write_env_breadcrumb(deleted: &Path) {
    if deleted.file_name().and_then(|n| n.to_str()) != Some(".env") {
        return;
    }
    match std::fs::write(deleted, ENV_BREADCRUMB) {
        Ok(()) => println!(
            "left a comment-only {} behind so tools that expect the file still find one",
            deleted.display()
        ),
        Err(e) => eprintln!("could not write the {} breadcrumb: {e}", deleted.display()),
    }
}

fn discovered_dotenv_files(path: &Path) -> Vec<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut files: Vec<_> = std::fs::read_dir(parent)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().is_file())
        .filter(|entry| entry.file_name().to_str().is_some_and(dotenv_like))
        .map(|entry| {
            if parent == Path::new(".") {
                PathBuf::from(entry.file_name())
            } else {
                entry.path()
            }
        })
        .collect();
    files.sort();
    files
}

fn layered_dotenv_maps(
    path: &Path,
    options: &ImportOptions,
) -> Result<Vec<(PathBuf, EnvName)>, CliError> {
    if path.file_name().and_then(|n| n.to_str()) != Some(".env") {
        if options.profile.is_some() {
            return Err(CliError::parse(
                "--profile requires the directory's .env path",
                None,
            ));
        }
        return Ok(Vec::new());
    }
    let parent = path.parent().unwrap_or(Path::new(""));
    let files = discovered_dotenv_files(path);
    let mut modes = BTreeSet::new();
    for file in &files {
        let Some(name) = file.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(mode) = name.strip_prefix(".env.") else {
            continue;
        };
        if mode == "local" || mode == "example" {
            continue;
        }
        let mode = mode.strip_suffix(".local").unwrap_or(mode);
        if EnvName::parse(mode).is_ok() {
            modes.insert(mode.to_owned());
        }
    }
    if options.profile.is_none() && !modes.is_empty() {
        return Err(CliError::parse(
            format!("mode-specific dotenv files need an explicit precedence choice: {}", files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")),
            Some("use import --profile nextjs or --profile vite, or ordered --map FILE=ENV entries; review with --plan".to_owned()),
        ));
    }
    let mut out = Vec::new();
    let mut add = |name: &str, env: &str| -> Result<(), CliError> {
        let file = parent.join(name);
        if file.is_file() {
            out.push((file, EnvName::parse(env).map_err(CliError::from)?));
        }
        Ok(())
    };
    match options.profile {
        Some(ImportProfile::Nextjs) => {
            // Base excludes .env.local so test never inherits it. Shared local
            // values are copied into development/production before mode-local.
            for mode in ["development", "production", "test"] {
                add(&format!(".env.{mode}"), mode)?;
                if mode != "test" {
                    add(".env.local", mode)?;
                }
                add(&format!(".env.{mode}.local"), mode)?;
            }
        }
        Some(ImportProfile::Vite) => {
            add(".env.local", "base")?;
            for mode in modes {
                if mode == "base" {
                    return Err(CliError::parse(
                        "Vite mode 'base' conflicts with the vault fallback; use explicit --map",
                        None,
                    ));
                }
                add(&format!(".env.{mode}"), &mode)?;
                add(&format!(".env.{mode}.local"), &mode)?;
            }
        }
        None => add(".env.local", "base")?,
    }
    Ok(out)
}

fn positional_dotenv_mode(path: &Path) -> Option<&str> {
    let suffix = path.file_name()?.to_str()?.strip_prefix(".env.")?;
    if matches!(suffix, "local" | "example") {
        return None;
    }
    Some(suffix.strip_suffix(".local").unwrap_or(suffix))
}

fn expand_sources(
    env: &EnvName,
    path: &Path,
    maps: &[String],
    options: &ImportOptions,
) -> Result<Vec<(PathBuf, EnvName)>, CliError> {
    if options.profile.is_some() && !maps.is_empty() {
        return Err(CliError::parse(
            "choose a profile or explicit mappings",
            None,
        ));
    }
    if options.profile.is_some() && env != &EnvName::base() {
        return Err(CliError::parse(
            "framework import profiles define their environments; omit --env",
            None,
        ));
    }
    // A positional production file must never inherit the implicit base env.
    // A mapping must name this file, not just some other source in the import.
    if let Some(mode) = positional_dotenv_mode(path) {
        let mapped = maps
            .iter()
            .map(|raw| parse_map_arg(raw))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|(file, _)| file == path);
        if !mapped && (env == &EnvName::base() || env.as_str() != mode) {
            return Err(CliError::parse(
                format!(
                    "{} is mode-specific and needs an explicit environment",
                    path.display()
                ),
                Some(format!(
                    "use --env {mode} import {}, or explicitly map this file with --map FILE=ENV",
                    path.display()
                )),
            ));
        }
    }
    let mut sources = build_sources(env, path, maps)?;
    if maps.is_empty() {
        let mut layered = layered_dotenv_maps(path, options)?;
        if options.profile.is_none() {
            // The ordinary .env/.env.local pair shares the selected target.
            for (_, target) in &mut layered {
                *target = env.clone();
            }
        }
        sources.extend(layered);
    }
    if options.profile.is_some() && !path.exists() {
        sources.retain(|(file, _)| file != path);
    }
    if sources.is_empty() {
        return Err(CliError::not_found(
            "no dotenv files matched the profile",
            None,
        ));
    }
    for (file, env) in &sources {
        eprintln!(
            "migration source: {} -> {} (later files win within each environment)",
            file.display(),
            env.as_str()
        );
    }
    report_remaining(path, &sources, false);
    Ok(sources)
}

fn declare_profile_environments(
    manifest: &mut Manifest,
    sources: &[(PathBuf, EnvName)],
    options: &ImportOptions,
) {
    if let Some(profile) = options.profile {
        let defaults: &[&str] = match profile {
            ImportProfile::Nextjs => &["development", "production", "test"],
            ImportProfile::Vite => &["development", "production"],
        };
        for name in defaults {
            ensure_env_declared(manifest, &EnvName::parse(name).expect("fixed environment"));
        }
        for (_, env) in sources {
            ensure_env_declared(manifest, env);
        }
    }
}

fn profile_next_step(options: &ImportOptions) {
    if options.profile.is_some() {
        eprintln!("select the imported environment when running: envholster --env development run -- npm run dev");
        eprintln!("use --env production for builds and --env test for Next.js tests; NODE_ENV does not select the vault environment");
    }
}

fn report_remaining(path: &Path, sources: &[(PathBuf, EnvName)], after: bool) {
    let selected: BTreeSet<_> = sources.iter().map(|(file, _)| file.clone()).collect();
    for file in discovered_dotenv_files(path) {
        if file.file_name().and_then(|n| n.to_str()) == Some(".env.example") {
            continue;
        }
        if after || !selected.contains(&file) {
            let breadcrumb = std::fs::metadata(&file)
                .is_ok_and(|m| m.len() == ENV_BREADCRUMB.len() as u64)
                && std::fs::read(&file)
                    .map(Zeroizing::new)
                    .is_ok_and(|b| b.as_slice() == ENV_BREADCRUMB.as_bytes());
            if !breadcrumb {
                eprintln!(
                    "plaintext file {}: {}",
                    if after {
                        "remaining"
                    } else {
                        "outside this migration"
                    },
                    file.display()
                );
            }
        }
    }
}

fn read_source_text(file: &Path) -> Result<String, CliError> {
    std::fs::read_to_string(file).map_err(|e| {
        CliError::not_found(
            format!("{} unreadable: {e}", file.display()),
            Some("pass an existing dotenv file to 'envholster import'".to_owned()),
        )
    })
}

fn parse_source(file_label: &str, text: &str) -> Result<Vec<DotenvEntry>, CliError> {
    let entries =
        parse_dotenv(text).map_err(|e| CliError::parse(format!("{file_label}: {e}"), None))?;
    // Readers split on a backtick-quoted value: Node and npm dotenv strip
    // the backticks (this parser follows them), python-dotenv and Compose
    // keep them. Say which reading was taken; names only, never the value.
    for entry in entries.iter().filter(|e| e.backtick_quoted) {
        eprintln!(
            "note: {file_label}:{} {} is backtick-quoted; imported the way Node reads it \
             (backticks stripped). A Python or Compose app would have seen the backticks: \
             set the value again with 'envholster set {}' if that is what it expects.",
            entry.line, entry.name, entry.name
        );
    }
    Ok(entries)
}

pub fn run(
    session: &mut Session,
    path: &Path,
    maps: &[String],
    options: &ImportOptions,
) -> Result<(), CliError> {
    let project = discover_project()?;
    let mut manifest = load_manifest(&project.manifest_path)?;
    let mut vault = open_vault(&project)?;

    let sources = expand_sources(&session.env, path, maps, options)?;
    declare_profile_environments(&mut manifest, &sources, options);

    // --- classify + confirm (values never echoed) ---
    let mut secrets: Vec<PlannedSecret> = Vec::new();
    let mut vars: Vec<PlannedVar> = Vec::new();
    let mut skipped = 0usize;
    let mut tier1_notice = false;
    for (file, env) in &sources {
        let text = Zeroizing::new(read_source_text(file)?);
        let entries = parse_source(&file.display().to_string(), &text)?;
        let hardware_enrolled = has_hardware_for(&vault, env, Tier::Sensitive);
        eprintln!(
            "importing {} into environment {:?} ({} entr{})",
            file.display(),
            env.as_str(),
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" }
        );
        for entry in entries {
            let suggestion = if options.encrypt_all {
                Suggestion {
                    class: Classification::Secret(1),
                    confident: true,
                }
            } else {
                classify(&entry.name, &entry.value)
            };
            let decision: Option<Classification> = match suggestion.class {
                // Review proposed plaintext together after precedence is resolved.
                Classification::Var => {
                    eprintln!(
                        "  {}:{} {} -> proposed plaintext setting",
                        file.display(),
                        entry.line,
                        entry.name
                    );
                    Some(Classification::Var)
                }
                Classification::Secret(_) if options.encrypt_all => Some(Classification::Secret(
                    declared_tier(&manifest, &entry.name, env).as_u8(),
                )),
                Classification::Secret(_) => {
                    // Disclosed BEFORE confirmation: a recognized provider
                    // key is stored with mode api-key.
                    let api_key = providers::recognize(&entry.name, &entry.value)
                        .map(|p| format!("; {} API key, mode api-key", p.hosts.join(", ")))
                        .unwrap_or_default();
                    if !hardware_enrolled {
                        // Without a hardware recipient, tier 1 is the only
                        // tier a cell can be created at: nothing to ask.
                        eprintln!(
                            "  {}:{} {} -> secret (tier 1{api_key})",
                            file.display(),
                            entry.line,
                            entry.name
                        );
                        tier1_notice = true;
                        Some(Classification::Secret(1))
                    } else {
                        let describe = match suggestion.class {
                            Classification::Secret(t) => format!("secret tier {t}{api_key}"),
                            Classification::Var => unreachable!("matched above"),
                        };
                        let marker = if suggestion.confident {
                            ""
                        } else {
                            " (unsure — please confirm)"
                        };
                        loop {
                            let answer = prompt_line(
                                &format!(
                                    "  {}:{} {} -> suggested {describe}{marker} \
                                     [Enter=accept, v=var, 1/2/3=secret tier, s=skip]: ",
                                    file.display(),
                                    entry.line,
                                    entry.name
                                ),
                                "every tier assignment is confirmed interactively; \
                                 import needs a terminal or scripted stdin",
                            )?;
                            match answer.as_str() {
                                "" => break Some(suggestion.class),
                                "v" | "var" => break Some(Classification::Var),
                                "1" => break Some(Classification::Secret(1)),
                                "2" => break Some(Classification::Secret(2)),
                                "3" => break Some(Classification::Secret(3)),
                                "s" | "skip" => break None,
                                _ => eprintln!("    enter one of: <Enter>, v, 1, 2, 3, s"),
                            }
                        }
                    }
                }
            };
            if decision.is_some() {
                discard_earlier(&mut secrets, &mut vars, env, &entry.name);
            }
            match decision {
                None => skipped += 1,
                Some(Classification::Var) => {
                    vars.push(PlannedVar {
                        env: env.clone(),
                        name: entry.name,
                        value: entry.value,
                    });
                }
                Some(Classification::Secret(raw)) => {
                    let tier = Tier::try_from_u8(raw).expect("prompt admits only 1-3");
                    secrets.push(PlannedSecret::new(env, tier, entry.name, entry.value));
                }
            }
        }
    }

    let encrypted_names = encrypted_names(&manifest, &secrets);
    let mut remaining = Vec::new();
    for var in vars.drain(..) {
        if encrypted_names.contains(&var.name) {
            eprintln!(
                "  {} / {} stays encrypted to preserve secret overrides",
                var.env.as_str(),
                var.name
            );
            let tier = declared_tier(&manifest, &var.name, &var.env);
            secrets.push(PlannedSecret::new(&var.env, tier, var.name, var.value));
        } else {
            remaining.push(var);
        }
    }
    vars = remaining;
    for secret in &mut secrets {
        if manifest.secret_decl(&secret.name, &secret.env).is_some() {
            secret.tier = declared_tier(&manifest, &secret.name, &secret.env);
        } else {
            secret.tier = secret
                .tier
                .max(declared_tier(&manifest, &secret.name, &secret.env));
        }
    }
    if !vars.is_empty() {
        eprintln!("Proposed plaintext settings in envholster.toml (values hidden):");
        for var in &vars {
            eprintln!("  {} / {}", var.env.as_str(), var.name);
        }
        let answer = prompt_line(
            "Store these listed settings in plaintext? [y/N; default encrypts them]: ",
            "review the names above, or use --encrypt-all or --plan/--apply",
        )?;
        if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
            for var in vars.drain(..) {
                secrets.push(PlannedSecret::new(
                    &var.env,
                    Tier::Ambient,
                    var.name,
                    var.value,
                ));
            }
        }
    }

    if tier1_notice {
        eprintln!("no hardware recipient enrolled: secrets stored at tier 1");
    }

    let outcome = write_planned(
        session,
        &project,
        &mut manifest,
        &mut vault,
        &mut secrets,
        &vars,
    )?;

    println!(
        "import complete: {} secret(s) added, {} updated, {} var(s) written to the \
         manifest, {skipped} skipped",
        outcome.added,
        outcome.updated,
        vars.len()
    );
    print_posture_lines(&outcome);

    // The vault is saved by now. Cleanup questions take their defaults when
    // nobody can answer, so an agent-driven import still succeeds.
    for file in sources
        .iter()
        .map(|(file, _)| file)
        .collect::<BTreeSet<_>>()
    {
        let Some(answer) = prompt_line_or_default(&format!(
            "Delete the imported plaintext file {} now? [y/N]: ",
            file.display()
        ))?
        else {
            eprintln!(
                "no answer, so {} was kept; delete it once 'envholster run' works for this project",
                file.display()
            );
            continue;
        };
        if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
            match std::fs::remove_file(file) {
                Ok(()) => {
                    println!("deleted {}", file.display());
                    write_env_breadcrumb(file);
                }
                Err(e) => eprintln!("could not delete {}: {e}", file.display()),
            }
        }
    }
    offer_gitignore(&project.root, &sources)?;
    report_remaining(path, &sources, true);
    profile_next_step(options);

    println!("{HISTORY_WARNING}");
    Ok(())
}

fn encrypted_names(manifest: &Manifest, secrets: &[PlannedSecret]) -> BTreeSet<String> {
    manifest
        .secrets
        .iter()
        .map(|d| d.name.clone())
        .chain(secrets.iter().map(|s| s.name.clone()))
        .collect()
}

fn declared_tier(manifest: &Manifest, name: &str, env: &EnvName) -> Tier {
    let (_, selected) = manifest.declared_max_tier(name, env);
    let (_, base) = manifest.declared_max_tier(name, &EnvName::base());
    selected.or(base).unwrap_or(Tier::Ambient)
}

fn discard_earlier(
    secrets: &mut Vec<PlannedSecret>,
    vars: &mut Vec<PlannedVar>,
    env: &EnvName,
    name: &str,
) {
    for secret in secrets
        .iter_mut()
        .filter(|s| &s.env == env && s.name == name)
    {
        secret.value.zeroize();
    }
    secrets.retain(|s| &s.env != env || s.name != name);
    for var in vars.iter_mut().filter(|v| &v.env == env && v.name == name) {
        var.value.zeroize();
    }
    vars.retain(|v| &v.env != env || v.name != name);
}

/// What [`write_planned`] wrote, for the human summary and the `--apply`
/// JSON: counts plus the names recognized as provider API keys (names only
/// — never values).
struct WriteOutcome {
    added: usize,
    updated: usize,
    /// Stored with mode `api-key` (a recognized provider key).
    brokered: Vec<String>,
}

/// The shared write path behind interactive `run` and `--apply`: the
/// hardware gate FIRST (a refusal provably leaves vault and manifest bytes
/// untouched), then vault save (authoritative), then manifest —
/// all-or-nothing, values zeroized after the save.
fn write_planned(
    session: &mut Session,
    project: &Project,
    manifest: &mut Manifest,
    vault: &mut Vault,
    secrets: &mut [PlannedSecret],
    vars: &[PlannedVar],
) -> Result<WriteOutcome, CliError> {
    // Tier >= 2 needs a hardware recipient to wrap to; checked before
    // anything is written.
    for planned in secrets.iter() {
        if planned.tier >= Tier::Sensitive && !has_hardware_for(vault, &planned.env, planned.tier) {
            return Err(CliError::denied(
                format!(
                    "no hardware recipient enrolled for tier {} (env {})",
                    planned.tier.as_u8(),
                    planned.env.as_str()
                ),
                Some(
                    "import at tier 1, or enroll hardware first: envholster recipient add \
                     <age1yubikey1...|age1se1...> --class hardware --label <label>"
                        .to_owned(),
                ),
            ));
        }
    }

    // --- apply: vault first (authoritative), then manifest ---
    // Every save re-encrypts every persisted cell; unlock them all up front.
    unlock_all_persisted(vault, session)?;
    let mut outcome = WriteOutcome {
        added: 0,
        updated: 0,
        brokered: Vec::new(),
    };
    let mut by_cell: BTreeMap<CellId, Vec<&PlannedSecret>> = BTreeMap::new();
    for planned in secrets.iter() {
        by_cell
            .entry(CellId {
                env: planned.env.clone(),
                tier: planned.tier,
            })
            .or_default()
            .push(planned);
    }
    for (cell, group) in &by_cell {
        session.unlock(vault, cell)?;
        for planned in group {
            let value = SecretBytes::try_from_slice(planned.value.as_bytes())
                .map_err(|e| CliError::failure(format!("locked allocation failed: {e}"), None))?;
            let existing_mode = vault
                .get_secret(cell, &planned.name)
                .ok()
                .map(|record| record.mode);
            let decl_mode = match existing_mode {
                Some(prior_mode) => {
                    // Value-only update: the existing record keeps its mode
                    // and posture — re-import never silently re-postures a
                    // secret the operator may have tuned. (A declaration, if
                    // missing, is written to MATCH the existing record.)
                    vault
                        .edit_secret(cell, &planned.name, value)
                        .map_err(CliError::from)?;
                    outcome.updated += 1;
                    prior_mode
                }
                None => {
                    let now = now_epoch();
                    vault
                        .add_secret(
                            cell,
                            &planned.name,
                            SecretRecord {
                                value,
                                // A recognized provider key is labelled
                                // api-key (a future proxy layer keys on it);
                                // everything else from a dotenv stays an env
                                // var by origin.
                                mode: planned.mode(),
                                guarantee: Guarantee::Unassigned,
                                created_at: now,
                                updated_at: now,
                                rotated_at: now,
                                rotate_after: None,
                                needs_rotation: false,
                                metadata: BTreeMap::new(),
                            },
                        )
                        .map_err(CliError::from)?;
                    outcome.added += 1;
                    if planned.provider.is_some() && !outcome.brokered.contains(&planned.name) {
                        outcome.brokered.push(planned.name.clone());
                    }
                    planned.mode()
                }
            };
            ensure_secret_decl(
                manifest,
                &planned.name,
                &planned.env,
                planned.tier,
                decl_mode,
            );
            let previous = if planned.env == EnvName::base() {
                manifest.vars.remove(&planned.name)
            } else {
                manifest
                    .envs
                    .get_mut(planned.env.as_str())
                    .and_then(|env| env.vars.remove(&planned.name))
            };
            if let Some(mut previous) = previous {
                previous.zeroize();
            }
        }
    }
    let wrote_cells = !by_cell.is_empty();
    drop(by_cell);
    if wrote_cells {
        vault.save().map_err(CliError::from)?;
    }
    for planned in secrets.iter_mut() {
        planned.value.zeroize();
    }

    for var in vars {
        ensure_env_declared(manifest, &var.env);
        if var.env.as_str() == envholster_core::constants::BASE_ENV {
            manifest.vars.insert(var.name.clone(), var.value.clone());
        } else {
            manifest
                .envs
                .entry(var.env.as_str().to_owned())
                .or_default()
                .vars
                .insert(var.name.clone(), var.value.clone());
        }
    }
    store_manifest(&project.manifest_path, manifest)?;
    // The vault is now worth merging: make sure git knows how (init does the
    // same; a project imported into an older checkout gets it here).
    crate::commands::merge_driver::ensure_merge_driver(&project.root);
    Ok(outcome)
}

/// The posture lines shared by interactive `run` and non-JSON `--apply`
/// (stderr, like the other progress lines). Names only, never values.
fn print_posture_lines(outcome: &WriteOutcome) {
    for name in &outcome.brokered {
        eprintln!(
            "api-key: {name} is a recognized provider key and is stored with mode api-key; \
             'envholster run' delivers it as a plain environment value in this version"
        );
    }
}

fn offer_gitignore(root: &Path, sources: &[(PathBuf, EnvName)]) -> Result<(), CliError> {
    let path = root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let has_rule = gitignore_covers_sources(root, sources);
    let has_local = gitignore_has_local(&existing);
    let has_locks = gitignore_has_locks(&existing);
    if has_rule && has_local && has_locks {
        return Ok(());
    }
    let missing = [
        (has_rule, "'.env*'"),
        (has_local, "'envholster.local.toml'"),
        (has_locks, "'*.envholster.lock'"),
    ]
    .into_iter()
    .filter_map(|(present, name)| (!present).then_some(name))
    .collect::<Vec<_>>()
    .join(", ");
    let answer = prompt_line_or_default(&format!(
        "Append {} to {}? [Y/n]: ",
        missing,
        path.display()
    ))?
    .unwrap_or_else(|| {
        eprintln!("no answer, so the ignore rules were added (the default)");
        String::new()
    });
    if answer.is_empty() || answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        write_gitignore_rules(&path, &existing, has_rule, has_local)?;
        println!("updated {}", path.display());
        warn_uncovered_sources(&uncovered_sources(root, sources));
    }
    Ok(())
}

/// A retained source that git would still commit AFTER the root rule was
/// written: tracked (ignore rules never apply to the index), or un-ignored
/// by a rule the root cannot override — a nested `.gitignore` carrying
/// `!.env.production` beats the root's `.env*`. Asked again after the write
/// because "appended `.env*`" and "the file is now safe" are different
/// claims, and only the second one is worth printing. Deleted sources are
/// skipped: there is nothing left to commit.
fn uncovered_sources(root: &Path, sources: &[(PathBuf, EnvName)]) -> Vec<(PathBuf, bool)> {
    sources
        .iter()
        .map(|(file, _)| file)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|file| file.is_file())
        .filter(|file| !super::run::dotenv_path_is_ignored(root, file))
        .map(|file| (file.clone(), super::run::git_tracks(root, file)))
        .collect()
}

fn warn_uncovered_sources(uncovered: &[(PathBuf, bool)]) {
    for (file, tracked) in uncovered {
        if *tracked {
            eprintln!(
                "WARNING: git tracks {}; no ignore rule applies to a tracked file, so it is still \
                 committable. Stop tracking it: git rm --cached {}",
                file.display(),
                file.display()
            );
        } else {
            eprintln!(
                "WARNING: git still does not ignore {} after updating .gitignore (a nested \
                 .gitignore or a later rule overrides it); the plaintext file is still committable",
                file.display()
            );
        }
    }
}

/// Is EVERY selected source file already kept out of git? `.env`, `*.env`,
/// and `.env*` are not interchangeable: the first two leave a layered
/// `.env.production` or `.env.production.local` committable, and a later
/// `!.env.production` revokes even `.env*`. So the question is asked per
/// file through the same effective evaluation `run --dotenv` uses (git first,
/// the frozen root-rule fallback without git). One uncovered file means the
/// cleanup appends `.env*`; as the last rule it wins over an earlier negation.
fn gitignore_covers_sources(root: &Path, sources: &[(PathBuf, EnvName)]) -> bool {
    sources
        .iter()
        .all(|(file, _)| super::run::dotenv_path_is_ignored(root, file))
}

fn gitignore_has_local(existing: &str) -> bool {
    existing
        .lines()
        .any(|l| l.trim() == "envholster.local.toml")
}

fn gitignore_has_locks(existing: &str) -> bool {
    existing
        .lines()
        .any(|line| line.trim() == "*.envholster.lock")
}

fn write_gitignore_rules(
    path: &Path,
    existing: &str,
    has_rule: bool,
    has_local: bool,
) -> Result<(), CliError> {
    let mut updated = existing.to_owned();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    if !has_rule {
        updated.push_str(".env*\n");
    }
    if !has_local {
        updated.push_str("envholster.local.toml\n");
    }
    if !gitignore_has_locks(existing) {
        updated.push_str("*.envholster.lock\n");
    }
    std::fs::write(path, updated)?;
    Ok(())
}

/// The unprompted form behind `--apply`'s explicit `gitignore=yes` — same
/// rules as the interactive offer, no question asked (the decisions file
/// already carries the human's explicit boolean, c40). Returns whether the
/// file changed.
fn apply_gitignore(root: &Path, sources: &[(PathBuf, EnvName)]) -> Result<bool, CliError> {
    let path = root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let has_rule = gitignore_covers_sources(root, sources);
    let has_local = gitignore_has_local(&existing);
    if has_rule && has_local && gitignore_has_locks(&existing) {
        return Ok(false);
    }
    write_gitignore_rules(&path, &existing, has_rule, has_local)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// §4.2 --plan: non-interactive, read-only; names/lines/lengths only
// ---------------------------------------------------------------------------

struct PlanEntry {
    file: String,
    line: usize,
    name: String,
    env: String,
    suggestion: Suggestion,
    value_chars: usize,
}

struct PlanDuplicate {
    file: String,
    name: String,
    lines: Vec<usize>,
}

/// The digest a plan is bound to: every source's label, environment and raw
/// bytes, in source order. `--apply` recomputes it and refuses when it
/// differs, so a decision reviewed against one value can never be applied
/// to another (a var decision applied to a line that now holds a credential
/// would write it to the plaintext manifest).
///
/// KEYED, never a bare hash: the digest is printed, and a plan consumer or a
/// log may keep it. A bare SHA-256 over the file bytes would let anyone
/// holding the digest confirm a guess at a low-entropy value (`PIN=0420`) by
/// hashing candidates. The key lives only on this machine (`plan-key` in the
/// config dir, 0600), so the digest reveals nothing about the values to
/// whoever reads the plan.
pub(crate) fn plan_digest(key: &[u8], sources: &[(String, String, String)]) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    for (label, env, text) in sources {
        bytes.extend_from_slice(label.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(env.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(text.len().to_string().as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(text.as_bytes());
        bytes.push(0);
    }
    let digest = envholster_core::hmac_sha256_hex_lower(key, &bytes);
    bytes.zeroize();
    digest
}

/// The machine-local key `plan_digest` uses, created on first use. Two
/// first-use callers may race (two `import` processes, or the unit tests
/// in one process): the key is written to a private temp file and
/// hard-linked into place, which is atomic and never replaces an existing
/// key, so whichever caller loses simply reads the winner's key.
fn plan_key() -> Result<SecretBytes, CliError> {
    let dir = crate::context::config_dir();
    let path = dir.join("plan-key");
    if !path.exists() {
        crate::context::create_secret_dir(&dir)?;
        let fresh = SecretBytes::try_random(32)
            .map_err(|e| CliError::failure(format!("entropy failure: {e}"), None))?;
        let tmp = dir.join(format!(
            "plan-key.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fresh.with_exposed(|k| crate::context::write_secret_file_exclusive(&tmp, k))?;
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(CliError::from(e));
            }
        }
        let _ = std::fs::remove_file(&tmp);
    }
    let mut bytes = std::fs::read(&path)?;
    let key = SecretBytes::try_from_slice(&bytes)
        .map_err(|e| CliError::failure(format!("locked allocation failed: {e}"), None));
    bytes.zeroize();
    let key = key?;
    if key.len() != 32 {
        return Err(CliError::failure(
            format!("{} is not a 32-byte plan key", path.display()),
            Some(format!(
                "rm {} and re-run; plans made before must be redone",
                path.display()
            )),
        ));
    }
    Ok(key)
}

/// Names and keyed fingerprints survive an interrupted setup; plaintext does not.
#[derive(Clone)]
pub(crate) struct GuidedSource {
    pub path: PathBuf,
    pub env: EnvName,
    pub fingerprint: String,
}

#[derive(Clone)]
pub(crate) struct GuidedValue {
    pub env: EnvName,
    pub name: String,
    pub fingerprint: String,
}

#[derive(Clone, Default)]
pub(crate) struct GuidedPlan {
    pub sources: Vec<GuidedSource>,
    pub values: Vec<GuidedValue>,
}

fn guided_error(message: impl Into<String>) -> CliError {
    CliError::failure(message, Some("envholster setup".to_owned()))
}

fn guided_text(path: &Path) -> Result<Zeroizing<String>, CliError> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    crate::setup::safe_path(path)?;
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file() || before.nlink() != 1 || before.len() > 1024 * 1024 {
        return Err(guided_error(format!(
            "{} must be an unshared regular dotenv file under 1 MiB",
            path.display()
        )));
    }
    let file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    if before.ino() != opened.ino() || before.dev() != opened.dev() {
        return Err(guided_error(
            "A dotenv file changed while setup was reading it",
        ));
    }
    let mut text = Zeroizing::new(String::new());
    file.take(1024 * 1024 + 1).read_to_string(&mut text)?;
    if text.len() > 1024 * 1024 {
        return Err(guided_error("A dotenv file exceeds 1 MiB"));
    }
    Ok(text)
}

fn guided_entries(path: &Path, text: &str) -> Result<Vec<DotenvEntry>, CliError> {
    if !find_duplicate_names(text).is_empty() {
        return Err(guided_error(format!("{} assigns a name more than once. Resolve duplicates before setup; the original is unchanged.", path.display())));
    }
    // Automatic migration accepts the common literal subset. Readers disagree
    // about expansion, escapes and backticks; retaining a file beats changing a key.
    if text.contains(['$', '\\', '`']) {
        return Err(guided_error(format!(
            "{} uses interpolation, escapes or backticks. Use explicit `envholster import` to review its reader semantics; automatic setup kept the original.",
            path.display()
        )));
    }
    envholster_core::dotenv::parse_setup_dotenv(text).map_err(|_| {
        guided_error(format!(
            "{} has unsupported dotenv syntax. Review it before setup; values are not displayed.",
            path.display()
        ))
    })
}

fn guided_fingerprint(key: &SecretBytes, label: &str, env: &str, bytes: &[u8]) -> String {
    let mut input = Zeroizing::new(Vec::new());
    input.extend_from_slice(label.as_bytes());
    input.push(0);
    input.extend_from_slice(env.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    key.with_exposed(|key| envholster_core::hmac_sha256_hex_lower(key, &input))
}

pub(crate) fn guided_plan(
    root: &Path,
    profile: Option<ImportProfile>,
) -> Result<GuidedPlan, CliError> {
    if !discovered_dotenv_files(&root.join(".env"))
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n != ".env.example"))
    {
        return Ok(GuidedPlan::default());
    }
    let options = ImportOptions {
        profile,
        encrypt_all: true,
    };
    let path = root.join(".env");
    let sources = if !path.is_file() && profile.is_none() {
        let local = root.join(".env.local");
        if local.is_file() {
            vec![(local, EnvName::base())]
        } else {
            vec![]
        }
    } else {
        expand_sources(&EnvName::base(), &path, &[], &options)?
    };
    let key = plan_key()?;
    let mut result = GuidedPlan::default();
    let mut values = BTreeMap::new();
    for (path, env) in sources {
        let text = guided_text(&path)?;
        if text.as_str() == ENV_BREADCRUMB {
            continue;
        }
        let entries = guided_entries(&path, &text)?;
        result.sources.push(GuidedSource {
            fingerprint: guided_fingerprint(
                &key,
                &path.to_string_lossy(),
                "source",
                text.as_bytes(),
            ),
            path,
            env: env.clone(),
        });
        for mut entry in entries {
            let fingerprint =
                guided_fingerprint(&key, &entry.name, env.as_str(), entry.value.as_bytes());
            entry.value.zeroize();
            values.insert(
                (env.clone(), entry.name.clone()),
                GuidedValue {
                    env: env.clone(),
                    name: entry.name,
                    fingerprint,
                },
            );
        }
    }
    result.values = values.into_values().collect();
    Ok(result)
}

/// Reuse the import write path, retaining originals for independent verification.
pub(crate) fn guided_apply(
    session: &mut Session,
    project: &Project,
    plan: &GuidedPlan,
    profile: Option<ImportProfile>,
) -> Result<(), CliError> {
    let key = plan_key()?;
    let mut manifest = load_manifest(&project.manifest_path)?;
    declare_profile_environments(
        &mut manifest,
        &plan
            .sources
            .iter()
            .map(|s| (s.path.clone(), s.env.clone()))
            .collect::<Vec<_>>(),
        &ImportOptions {
            profile,
            encrypt_all: true,
        },
    );
    let mut vault = open_vault(project)?;
    let mut secrets = Vec::new();
    for source in &plan.sources {
        let text = guided_text(&source.path)?;
        if guided_fingerprint(
            &key,
            &source.path.to_string_lossy(),
            "source",
            text.as_bytes(),
        ) != source.fingerprint
        {
            return Err(guided_error("A dotenv file changed since the reviewed plan. Rerun setup to review it; originals were kept."));
        }
        for mut entry in guided_entries(&source.path, &text)? {
            discard_earlier(&mut secrets, &mut Vec::new(), &source.env, &entry.name);
            let tier = declared_tier(&manifest, &entry.name, &source.env);
            secrets.push(PlannedSecret::new(
                &source.env,
                tier,
                entry.name.clone(),
                std::mem::take(&mut entry.value),
            ));
        }
    }
    let outcome = write_planned(
        session,
        project,
        &mut manifest,
        &mut vault,
        &mut secrets,
        &[],
    )?;
    println!(
        "Imported {} new and {} updated encrypted values.",
        outcome.added, outcome.updated
    );
    drop(vault);
    guided_verify(session, project, plan)?;
    apply_gitignore(
        &project.root,
        &plan
            .sources
            .iter()
            .map(|s| (s.path.clone(), s.env.clone()))
            .collect::<Vec<_>>(),
    )?;
    Ok(())
}

pub(crate) fn guided_verify(
    session: &mut Session,
    project: &Project,
    plan: &GuidedPlan,
) -> Result<(), CliError> {
    let key = plan_key()?;
    let manifest = load_manifest(&project.manifest_path)?;
    let mut vault = open_vault(project)?;
    for expected in &plan.values {
        manifest
            .secret_decl(&expected.name, &expected.env)
            .ok_or_else(|| {
                guided_error("An imported value has no encrypted declaration; originals were kept")
            })?;
        let cell = CellId {
            env: expected.env.clone(),
            tier: declared_tier(&manifest, &expected.name, &expected.env),
        };
        session.unlock(&mut vault, &cell)?;
        let record = vault
            .get_secret(&cell, &expected.name)
            .map_err(CliError::from)?;
        let actual = record.value.with_exposed(|bytes| {
            guided_fingerprint(&key, &expected.name, expected.env.as_str(), bytes)
        });
        if actual != expected.fingerprint {
            return Err(guided_error("An imported value differs from the reviewed source. Originals were kept; review changes before restarting setup."));
        }
    }
    Ok(())
}

pub(crate) fn guided_remove_source(source: &GuidedSource) -> Result<(), CliError> {
    let text = match guided_text(&source.path) {
        Ok(text) => text,
        Err(_) if !source.path.try_exists()? => return Ok(()),
        Err(error) => return Err(error),
    };
    if text.as_str() == ENV_BREADCRUMB {
        return Ok(());
    }
    let key = plan_key()?;
    if guided_fingerprint(
        &key,
        &source.path.to_string_lossy(),
        "source",
        text.as_bytes(),
    ) != source.fingerprint
    {
        return Err(guided_error(format!(
            "{} changed after import and was kept. Review it before cleanup.",
            source.path.display()
        )));
    }
    std::fs::remove_file(&source.path)?;
    if source.path.file_name().is_some_and(|s| s == ".env") {
        crate::context::write_secret_file_exclusive(&source.path, ENV_BREADCRUMB.as_bytes())?;
    }
    Ok(())
}

/// The decisions-file line a plan prints: bare, so it can be copied as is.
pub(crate) fn plan_line(digest: &str) -> String {
    format!("plan {digest}")
}

pub fn plan(
    session: &Session,
    path: &Path,
    maps: &[String],
    json: bool,
    options: &ImportOptions,
) -> Result<(), CliError> {
    let sources = expand_sources(&session.env, path, maps, options)?;
    let mut with_text: Zeroizing<Vec<(String, String, String)>> = Zeroizing::new(Vec::new());
    for (file, env) in &sources {
        with_text.push((
            file.display().to_string(),
            env.as_str().to_owned(),
            read_source_text(file)?,
        ));
    }
    let (mut entries, duplicates) = plan_from_texts(&with_text)?;
    if options.encrypt_all {
        for entry in &mut entries {
            entry.suggestion = Suggestion {
                class: Classification::Secret(1),
                confident: true,
            };
        }
    }
    let manifest = discover_project()
        .and_then(|project| load_manifest(&project.manifest_path))
        .ok();
    let mut secret_names: BTreeSet<String> = entries
        .iter()
        .filter(|e| matches!(e.suggestion.class, Classification::Secret(_)))
        .map(|e| e.name.clone())
        .collect();
    if let Some(manifest) = &manifest {
        secret_names.extend(manifest.secrets.iter().map(|d| d.name.clone()));
    }
    for entry in &mut entries {
        if secret_names.contains(&entry.name) {
            let env = EnvName::parse(&entry.env).map_err(CliError::from)?;
            let tier = manifest
                .as_ref()
                .map(|m| declared_tier(m, &entry.name, &env).as_u8())
                .unwrap_or(1);
            let suggested = match entry.suggestion.class {
                Classification::Secret(t) => t,
                Classification::Var => 1,
            };
            let existing = manifest
                .as_ref()
                .is_some_and(|m| m.secret_decl(&entry.name, &env).is_some());
            entry.suggestion.class =
                Classification::Secret(if existing { tier } else { tier.max(suggested) });
        }
    }
    let digest = plan_key()?.with_exposed(|k| plan_digest(k, &with_text));
    if json {
        let meta: Vec<(String, String)> = with_text
            .iter()
            .map(|(file, env, _)| (file.clone(), env.clone()))
            .collect();
        println!(
            "{}",
            render_plan_json(&meta, &entries, &duplicates, &digest)
        );
        return Ok(());
    }
    println!("{}", plan_line(&digest));
    eprintln!(
        "copy the 'plan ...' line above into the decisions file; --apply refuses if the \
         files change after this plan"
    );
    for entry in &entries {
        let unsure_marker = if entry.suggestion.confident {
            ""
        } else {
            " (unsure)"
        };
        let (kind, marker) = match entry.suggestion.class {
            Classification::Var => ("var".to_owned(), ""),
            Classification::Secret(t) => (format!("secret tier {t}"), unsure_marker),
        };
        println!(
            "{}:{} {} -> {kind}{marker} [{} chars]",
            entry.file, entry.line, entry.name, entry.value_chars
        );
    }
    for dup in &duplicates {
        println!(
            "duplicate: {} {} (lines {})",
            dup.file,
            dup.name,
            join_usizes(&dup.lines)
        );
    }
    Ok(())
}

fn plan_from_texts(
    sources: &[(String, String, String)],
) -> Result<(Vec<PlanEntry>, Vec<PlanDuplicate>), CliError> {
    let mut entries: Vec<PlanEntry> = Vec::new();
    let mut duplicates: Vec<PlanDuplicate> = Vec::new();
    for (file, env, text) in sources {
        for (name, lines) in find_duplicate_names(text) {
            duplicates.push(PlanDuplicate {
                file: file.clone(),
                name,
                lines,
            });
        }
        for mut entry in parse_source(file, text)? {
            entries.push(PlanEntry {
                file: file.clone(),
                line: entry.line,
                name: entry.name.clone(),
                env: env.clone(),
                suggestion: classify(&entry.name, &entry.value),
                value_chars: entry.value.chars().count(),
            });
            entry.value.zeroize();
        }
    }
    Ok((entries, duplicates))
}

/// Recovers EVERY assignment of each name, not just the surviving one:
/// `parse_dotenv` deliberately keeps only the last assignment (shell
/// semantics), so earlier occurrences are recovered from line-prefix parses —
/// a prefix ending inside a multiline quoted value fails to parse and is
/// skipped, which is exactly what keeps `KEY=`-shaped text INSIDE such a
/// value from being miscounted as an assignment. Quadratic in file length,
/// which dotenv files never stress; re-using the one real parser beats a
/// second hand-rolled scanner that could silently drift from it.
pub(crate) fn find_duplicate_names(text: &str) -> Vec<(String, Vec<usize>)> {
    let mut seen: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    let mut prefix = String::with_capacity(text.len());
    for line in text.lines() {
        prefix.push_str(line);
        prefix.push('\n');
        if let Ok(entries) = parse_dotenv(&prefix) {
            for mut entry in entries {
                seen.entry(entry.name.clone())
                    .or_default()
                    .insert(entry.line);
                entry.value.zeroize();
            }
        }
    }
    prefix.zeroize();
    seen.into_iter()
        .filter(|(_, lines)| lines.len() > 1)
        .map(|(name, lines)| (name, lines.into_iter().collect()))
        .collect()
}

fn join_usizes(values: &[usize]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_plan_json(
    sources: &[(String, String)],
    entries: &[PlanEntry],
    duplicates: &[PlanDuplicate],
    digest: &str,
) -> String {
    let mut out = String::from("{\"schema\":1,\"digest\":");
    json_escape_into(&mut out, digest);
    out.push_str(",\"sources\":[");
    for (i, (file, env)) in sources.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"file\":");
        json_escape_into(&mut out, file);
        out.push_str(",\"env\":");
        json_escape_into(&mut out, env);
        out.push('}');
    }
    out.push_str("],\"entries\":[");
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"file\":");
        json_escape_into(&mut out, &entry.file);
        out.push_str(&format!(",\"line\":{}", entry.line));
        out.push_str(",\"name\":");
        json_escape_into(&mut out, &entry.name);
        out.push_str(",\"env\":");
        json_escape_into(&mut out, &entry.env);
        out.push_str(",\"suggestion\":{\"kind\":");
        match entry.suggestion.class {
            Classification::Var => out.push_str("\"var\""),
            Classification::Secret(t) => out.push_str(&format!("\"secret\",\"tier\":{t}")),
        }
        out.push_str(&format!(
            ",\"confident\":{}}}",
            if entry.suggestion.confident {
                "true"
            } else {
                "false"
            }
        ));
        out.push_str(&format!(",\"value_chars\":{}}}", entry.value_chars));
    }
    out.push_str("],\"duplicates\":[");
    for (i, dup) in duplicates.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"file\":");
        json_escape_into(&mut out, &dup.file);
        out.push_str(",\"name\":");
        json_escape_into(&mut out, &dup.name);
        out.push_str(",\"lines\":[");
        for (j, line) in dup.lines.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&line.to_string());
        }
        out.push_str("]}");
    }
    out.push_str("]}");
    out
}

// ---------------------------------------------------------------------------
// §4.2 --apply: line-based decisions, exact cover, then the shared write path
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionAction {
    Var,
    Skip,
    Secret(u8),
}

#[derive(Debug)]
pub(crate) struct Decisions {
    /// The `plan <digest>` line: the plan these decisions were made against.
    plan_digest: String,
    delete_sources: bool,
    gitignore: bool,
    decide: BTreeMap<(String, String), DecisionAction>,
}

/// A malformed decisions file is a caller usage bug, so it shares clap's
/// argv/usage exit class (2, errors.rs).
fn decisions_invalid(detail: String) -> CliError {
    CliError::new(
        "IMPORT_DECISIONS_INVALID",
        2,
        format!("decisions file: {detail}"),
        Some(
            "grammar: 'version 1', the 'plan <digest>' line printed by --plan, one 'cleanup \
             delete_sources=<yes|no> gitignore=<yes|no>' line, then 'decide <file> <name> \
             var|skip' or 'decide <file> <name> secret <1|2|3>' per entry"
                .to_owned(),
        ),
    )
}

fn parse_yes_no(token: &str, lineno: usize, key: &str) -> Result<bool, CliError> {
    match token {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(decisions_invalid(format!(
            "line {lineno}: {key} must be yes or no, got {other:?}"
        ))),
    }
}

/// The decisions grammar is deliberately line-based, not JSON: the plan side
/// only ever EMITS JSON, so the dependency-frozen CLI needs no JSON parser
/// anywhere. Both cleanup booleans are required explicit (c40: no silent
/// cleanup defaults) and every malformed line is named by number.
pub(crate) fn parse_decisions(text: &str) -> Result<Decisions, CliError> {
    let mut version_seen = false;
    let mut plan_digest: Option<String> = None;
    let mut cleanup: Option<(bool, bool)> = None;
    let mut decide: BTreeMap<(String, String), DecisionAction> = BTreeMap::new();
    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !version_seen {
            if line != "version 1" {
                return Err(decisions_invalid(format!(
                    "line {lineno}: the first directive must be 'version 1', got {line:?}"
                )));
            }
            version_seen = true;
            continue;
        }
        let mut tokens = line.split_whitespace();
        match tokens.next() {
            Some("plan") => {
                let Some(digest) = tokens.next() else {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: plan takes the digest printed by --plan"
                    )));
                };
                if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: plan digest must be 64 hex characters"
                    )));
                }
                if tokens.next().is_some() {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: unexpected trailing tokens"
                    )));
                }
                if plan_digest.replace(digest.to_ascii_lowercase()).is_some() {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: duplicate plan line"
                    )));
                }
            }
            Some("cleanup") => {
                if cleanup.is_some() {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: duplicate cleanup line"
                    )));
                }
                let mut delete_sources: Option<bool> = None;
                let mut gitignore: Option<bool> = None;
                for token in tokens {
                    let Some((key, value)) = token.split_once('=') else {
                        return Err(decisions_invalid(format!(
                            "line {lineno}: cleanup takes key=value pairs, got {token:?}"
                        )));
                    };
                    let parsed = parse_yes_no(value, lineno, key)?;
                    let slot = match key {
                        "delete_sources" => &mut delete_sources,
                        "gitignore" => &mut gitignore,
                        other => {
                            return Err(decisions_invalid(format!(
                                "line {lineno}: unknown cleanup key {other:?}"
                            )))
                        }
                    };
                    if slot.replace(parsed).is_some() {
                        return Err(decisions_invalid(format!(
                            "line {lineno}: {key} given twice"
                        )));
                    }
                }
                let (Some(delete_sources), Some(gitignore)) = (delete_sources, gitignore) else {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: cleanup must state BOTH delete_sources and gitignore \
                         explicitly"
                    )));
                };
                cleanup = Some((delete_sources, gitignore));
            }
            Some("decide") => {
                let (Some(file), Some(name), Some(action)) =
                    (tokens.next(), tokens.next(), tokens.next())
                else {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: decide takes <file> <name> var|skip|secret <tier>"
                    )));
                };
                let action = match action {
                    "var" => DecisionAction::Var,
                    "skip" => DecisionAction::Skip,
                    "secret" => match tokens.next() {
                        Some("1") => DecisionAction::Secret(1),
                        Some("2") => DecisionAction::Secret(2),
                        Some("3") => DecisionAction::Secret(3),
                        other => {
                            return Err(decisions_invalid(format!(
                                "line {lineno}: secret tier must be 1, 2, or 3, got {other:?}"
                            )))
                        }
                    },
                    other => {
                        return Err(decisions_invalid(format!(
                            "line {lineno}: unknown action {other:?} (expected var, skip, or secret <tier>)"
                        )))
                    }
                };
                if tokens.next().is_some() {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: unexpected trailing tokens"
                    )));
                }
                if decide
                    .insert((file.to_owned(), name.to_owned()), action)
                    .is_some()
                {
                    return Err(decisions_invalid(format!(
                        "line {lineno}: duplicate decision for {file} {name}"
                    )));
                }
            }
            Some(other) => {
                return Err(decisions_invalid(format!(
                    "line {lineno}: unknown directive {other:?}"
                )))
            }
            None => unreachable!("blank lines are skipped above"),
        }
    }
    if !version_seen {
        return Err(decisions_invalid("missing 'version 1' line".to_owned()));
    }
    let Some((delete_sources, gitignore)) = cleanup else {
        return Err(decisions_invalid(
            "missing the cleanup line (both booleans are required explicit — c40)".to_owned(),
        ));
    };
    let Some(plan_digest) = plan_digest else {
        return Err(decisions_invalid(
            "missing the plan line: copy the 'plan <digest>' line printed by 'import --plan'"
                .to_owned(),
        ));
    };
    Ok(Decisions {
        plan_digest,
        delete_sources,
        gitignore,
        decide,
    })
}

/// Exact cover, proven server-side before anything is written: a decision
/// naming an entry the file no longer has means the file changed since
/// `--plan` (stale); an entry with no decision means the client skipped a
/// line silently — c40 forbids both.
pub(crate) fn check_cover(
    entries: &[(String, String)],
    decisions: &Decisions,
) -> Result<(), CliError> {
    let entry_set: BTreeSet<&(String, String)> = entries.iter().collect();
    let stale: Vec<String> = decisions
        .decide
        .keys()
        .filter(|key| !entry_set.contains(key))
        .map(|(file, name)| format!("{file}:{name}"))
        .collect();
    let missing: Vec<String> = entries
        .iter()
        .filter(|key| !decisions.decide.contains_key(key))
        .map(|(file, name)| format!("{file}:{name}"))
        .collect();
    if !stale.is_empty() {
        let mut message = format!(
            "the decisions no longer match the file(s): decisions without a matching entry: [{}]",
            stale.join(", ")
        );
        if !missing.is_empty() {
            message.push_str(&format!(
                "; entries without a decision: [{}]",
                missing.join(", ")
            ));
        }
        return Err(CliError::new(
            "IMPORT_PLAN_STALE",
            EXIT_FAILURE,
            message,
            Some(
                "the file changed since it was scanned — re-run 'envholster import <file> \
                 --plan', review again, and apply fresh decisions"
                    .to_owned(),
            ),
        ));
    }
    if !missing.is_empty() {
        return Err(CliError::new(
            "IMPORT_DECISION_MISSING",
            EXIT_FAILURE,
            format!(
                "entries with no decision: [{}] — every entry needs an explicit decision (c40: \
                 no silent default)",
                missing.join(", ")
            ),
            Some(
                "add a 'decide <file> <name> var|skip|secret <tier>' line for each listed entry"
                    .to_owned(),
            ),
        ));
    }
    Ok(())
}

pub fn apply(
    session: &mut Session,
    path: &Path,
    maps: &[String],
    decisions_path: &Path,
    json: bool,
    options: &ImportOptions,
) -> Result<(), CliError> {
    let project = discover_project()?;
    apply_in(session, &project, path, maps, decisions_path, json, options)
}

fn apply_in(
    session: &mut Session,
    project: &Project,
    path: &Path,
    maps: &[String],
    decisions_path: &Path,
    json: bool,
    options: &ImportOptions,
) -> Result<(), CliError> {
    let mut manifest = load_manifest(&project.manifest_path)?;
    let mut vault = open_vault(project)?;

    let sources = expand_sources(&session.env, path, maps, options)?;
    declare_profile_environments(&mut manifest, &sources, options);
    let decisions_text = std::fs::read_to_string(decisions_path).map_err(|e| {
        CliError::not_found(
            format!(
                "decisions file {} unreadable: {e}",
                decisions_path.display()
            ),
            Some("write a decisions file for the current plan, then retry --apply".to_owned()),
        )
    })?;
    let decisions = parse_decisions(&decisions_text)?;

    let mut parsed_sources: Vec<(String, EnvName, Vec<DotenvEntry>)> = Vec::new();
    let mut with_text: Zeroizing<Vec<(String, String, String)>> = Zeroizing::new(Vec::new());
    for (file, env) in &sources {
        let label = file.display().to_string();
        let text = Zeroizing::new(read_source_text(file)?);
        with_text.push((label.clone(), env.as_str().to_owned(), text.to_string()));
        let entries = parse_source(&label, &text)?;
        // The interactive path's last-assignment-wins shell semantics are NOT
        // silently replicated by the machine mode: a duplicated name means a
        // decision would ambiguously cover two lines, so apply refuses —
        // UNLESS the decision for that name is `skip`. Skipping is the one
        // unambiguous choice (no value is picked either way), and it is how a
        // client lets the human clear a duplicate without editing the file.
        let dups: Vec<(String, Vec<usize>)> = find_duplicate_names(&text)
            .into_iter()
            .filter(|(name, _)| {
                decisions
                    .decide
                    .get(&(label.clone(), name.clone()))
                    .copied()
                    != Some(DecisionAction::Skip)
            })
            .collect();
        if !dups.is_empty() {
            let listing = dups
                .iter()
                .map(|(name, lines)| format!("{label}: {name} (lines {})", join_usizes(lines)))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(CliError::new(
                "IMPORT_DUPLICATE_NAME",
                EXIT_FAILURE,
                format!("names assigned more than once cannot be applied: {listing}"),
                Some(
                    "decide 'skip' for the duplicated name to leave it out, or edit the file so \
                     each name appears exactly once, then re-run --plan and --apply"
                        .to_owned(),
                ),
            ));
        }
        parsed_sources.push((label, env.clone(), entries));
    }

    // The decisions were made against one exact set of bytes; anything else
    // (a value edited after review, a re-mapped environment) is a different
    // plan, refused before any write or cleanup.
    let now = plan_key()?.with_exposed(|k| plan_digest(k, &with_text));
    for (_, _, text) in with_text.iter_mut() {
        text.zeroize();
    }
    if now != decisions.plan_digest {
        return Err(CliError::new(
            "IMPORT_PLAN_STALE",
            EXIT_FAILURE,
            "the source file(s) or their environment mapping changed since the plan these \
             decisions were made against (plan digest mismatch)"
                .to_owned(),
            Some(
                "re-run 'envholster import <file> --plan', review the fresh plan, and apply \
                 decisions that carry its digest"
                    .to_owned(),
            ),
        ));
    }

    let keys: Vec<(String, String)> = parsed_sources
        .iter()
        .flat_map(|(label, _, entries)| {
            entries
                .iter()
                .map(move |entry| (label.clone(), entry.name.clone()))
        })
        .collect();
    check_cover(&keys, &decisions)?;

    let mut secrets: Vec<PlannedSecret> = Vec::new();
    let mut vars: Vec<PlannedVar> = Vec::new();
    let mut skipped = 0usize;
    for (label, env, entries) in parsed_sources {
        for mut entry in entries {
            let action = *decisions
                .decide
                .get(&(label.clone(), entry.name.clone()))
                .expect("exact cover checked above");
            if action != DecisionAction::Skip {
                discard_earlier(&mut secrets, &mut vars, &env, &entry.name);
            }
            match action {
                DecisionAction::Skip => {
                    skipped += 1;
                    entry.value.zeroize();
                }
                DecisionAction::Var => vars.push(PlannedVar {
                    env: env.clone(),
                    name: entry.name,
                    value: entry.value,
                }),
                DecisionAction::Secret(raw) => {
                    let tier = Tier::try_from_u8(raw).expect("decisions grammar admits only 1-3");
                    secrets.push(PlannedSecret::new(&env, tier, entry.name, entry.value));
                }
            }
        }
    }

    let secret_names = encrypted_names(&manifest, &secrets);
    for var in &vars {
        if secret_names.contains(&var.name) {
            return Err(CliError::parse(
                format!(
                    "{} / {} conflicts with an encrypted declaration or override",
                    var.env.as_str(),
                    var.name
                ),
                Some(
                    "review the plan and choose secret for this name in every environment"
                        .to_owned(),
                ),
            ));
        }
    }
    for secret in &secrets {
        let declared = declared_tier(&manifest, &secret.name, &secret.env);
        if secret.tier < declared
            || (manifest.secret_decl(&secret.name, &secret.env).is_some()
                && secret.tier != declared)
        {
            return Err(CliError::denied(
                format!(
                    "{} / {} would change an existing secret tier",
                    secret.env.as_str(),
                    secret.name
                ),
                Some("retain the declared tier in the decisions file".to_owned()),
            ));
        }
    }
    let outcome = write_planned(
        session,
        project,
        &mut manifest,
        &mut vault,
        &mut secrets,
        &vars,
    )?;

    // Cleanup per the explicit booleans, no prompting — the human already
    // answered in the decisions file.
    let mut deleted_sources: Vec<String> = Vec::new();
    if decisions.delete_sources {
        for file in sources
            .iter()
            .map(|(file, _)| file)
            .collect::<BTreeSet<_>>()
        {
            match std::fs::remove_file(file) {
                Ok(()) => deleted_sources.push(file.display().to_string()),
                Err(e) => eprintln!("could not delete {}: {e}", file.display()),
            }
        }
    }
    let gitignore_updated = if decisions.gitignore {
        apply_gitignore(&project.root, &sources)?
    } else {
        false
    };
    // Only a write is re-checked: when nothing needed writing, every retained
    // source already answered "ignored", which a tracked file cannot.
    let uncovered = if gitignore_updated {
        uncovered_sources(&project.root, &sources)
    } else {
        Vec::new()
    };

    print_posture_lines(&outcome);
    report_remaining(path, &sources, true);
    warn_uncovered_sources(&uncovered);
    profile_next_step(options);
    if json {
        let uncovered: Vec<String> = uncovered
            .iter()
            .map(|(file, _)| file.display().to_string())
            .collect();
        println!(
            "{}",
            render_apply_json(
                &outcome,
                vars.len(),
                skipped,
                &deleted_sources,
                gitignore_updated,
                &uncovered
            )
        );
        return Ok(());
    }
    println!(
        "import complete: {} secret(s) added, {} updated, {} var(s) written to the \
         manifest, {skipped} skipped",
        outcome.added,
        outcome.updated,
        vars.len()
    );
    for file in &deleted_sources {
        println!("deleted {file}");
    }
    if gitignore_updated {
        println!("updated {}", project.root.join(".gitignore").display());
    }
    println!("{HISTORY_WARNING}");
    Ok(())
}

fn render_apply_json(
    outcome: &WriteOutcome,
    vars: usize,
    skipped: usize,
    deleted_sources: &[String],
    gitignore_updated: bool,
    uncovered_sources: &[String],
) -> String {
    let mut out = format!(
        "{{\"schema\":1,\"added\":{},\"updated\":{},\"vars\":{vars},\
         \"skipped\":{skipped},\"deleted_sources\":[",
        outcome.added, outcome.updated
    );
    for (i, file) in deleted_sources.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_escape_into(&mut out, file);
    }
    out.push_str("],\"gitignore_updated\":");
    out.push_str(if gitignore_updated { "true" } else { "false" });
    out.push_str(",\"warning\":");
    json_escape_into(&mut out, HISTORY_WARNING);
    // Additive schema-1 fields (older consumers ignore unknown keys): the
    // names that landed in each strengthened posture. Names only, no values.
    out.push_str(",\"brokered\":[");
    for (i, name) in outcome.brokered.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_escape_into(&mut out, name);
    }
    // Retained sources git would still commit after the `.gitignore` write
    // (tracked, or un-ignored by a nested rule). Empty when the write covered
    // every file; a consumer that reads only `gitignore_updated` must not take
    // `true` as "safe to commit".
    out.push_str("],\"uncovered_sources\":[");
    for (i, file) in uncovered_sources.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_escape_into(&mut out, file);
    }
    out.push_str("]}");
    out
}

// ---------------------------------------------------------------------------
// §4.2 --detect: names only, so the app never globs the project itself
// ---------------------------------------------------------------------------

pub(crate) fn dotenv_like(name: &str) -> bool {
    if name.ends_with(".envholster.lock") {
        return false;
    }

    name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
}

pub fn detect(json: bool) -> Result<(), CliError> {
    let project = discover_project()?;
    let mut files: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&project.root) {
        for entry in entries.flatten() {
            if !entry.path().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if dotenv_like(&name) {
                files.push(name);
            }
        }
    }
    files.sort();
    if json {
        let mut out = String::from("{\"schema\":1,\"files\":[");
        for (i, file) in files.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_escape_into(&mut out, file);
        }
        out.push_str("]}");
        println!("{out}");
        return Ok(());
    }
    for file in &files {
        println!("{file}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_json_golden() {
        let text = "PORT=8080\nMYSTERY=opaque-ish\nFOO=1\nFOO=2\n";
        let sources = vec![(".env".to_owned(), "base".to_owned(), text.to_owned())];
        let (entries, duplicates) = plan_from_texts(&sources).unwrap();
        let meta = vec![(".env".to_owned(), "base".to_owned())];
        let digest = plan_digest(b"test-key", &sources);
        assert_eq!(digest.len(), 64);
        assert_ne!(
            digest,
            plan_digest(b"other-key", &sources),
            "the digest must depend on the key, or a published plan would verify guesses"
        );
        let json = render_plan_json(&meta, &entries, &duplicates, &digest);
        assert!(json.starts_with(&format!("{{\"schema\":1,\"digest\":\"{digest}\",")));
        assert_eq!(
            json[json.find(",\"sources\"").unwrap() + 1..].to_string(),
            "\"sources\":[{\"file\":\".env\",\"env\":\"base\"}],\
             \"entries\":[\
             {\"file\":\".env\",\"line\":1,\"name\":\"PORT\",\"env\":\"base\",\
             \"suggestion\":{\"kind\":\"var\",\"confident\":true},\"value_chars\":4},\
             {\"file\":\".env\",\"line\":2,\"name\":\"MYSTERY\",\"env\":\"base\",\
             \"suggestion\":{\"kind\":\"secret\",\"tier\":1,\"confident\":false},\
             \"value_chars\":10},\
             {\"file\":\".env\",\"line\":4,\"name\":\"FOO\",\"env\":\"base\",\
             \"suggestion\":{\"kind\":\"var\",\"confident\":true},\"value_chars\":1}],\
             \"duplicates\":[{\"file\":\".env\",\"name\":\"FOO\",\"lines\":[3,4]}]}"
        );
    }

    #[test]
    fn plan_json_never_contains_a_value() {
        let text = "SECRET_TOKEN=hunter2-super-secret\n";
        let sources = vec![(".env".to_owned(), "base".to_owned(), text.to_owned())];
        let (entries, duplicates) = plan_from_texts(&sources).unwrap();
        let json = render_plan_json(
            &[(".env".to_owned(), "base".to_owned())],
            &entries,
            &duplicates,
            "digest-under-test",
        );
        assert!(!json.contains("hunter2"));
        assert!(json.contains("\"value_chars\":20"));
    }

    /// The app's plan seam always invokes `import <file> --map <file>=<env>`.
    /// A map naming the positional file must OVERRIDE its env, not append the
    /// same file as a second source — the append bug planned every entry
    /// twice (doubled review tables, doubled unsure counts) and would have
    /// applied the file into both envs.
    /// A path may hold `=`; only the last one separates file from env.
    #[test]
    fn import_tier_uses_selected_scope_before_base_fallback() {
        let mut manifest = Manifest::parse("schema = 1\n").unwrap();
        let base = EnvName::base();
        let dev = EnvName::parse("development").unwrap();
        let prod = EnvName::parse("production").unwrap();
        ensure_secret_decl(
            &mut manifest,
            "KEY",
            &base,
            Tier::Critical,
            SecretMode::EnvVar,
        );
        ensure_secret_decl(
            &mut manifest,
            "KEY",
            &dev,
            Tier::Ambient,
            SecretMode::EnvVar,
        );
        assert_eq!(declared_tier(&manifest, "KEY", &dev), Tier::Ambient);
        assert_eq!(declared_tier(&manifest, "KEY", &prod), Tier::Critical);
    }

    #[test]
    fn map_arg_splits_on_the_last_equals() {
        let (file, env) = parse_map_arg("config=prod/.env.local=base").unwrap();
        assert_eq!(file, Path::new("config=prod/.env.local"));
        assert_eq!(env.as_str(), "base");
        let (file, env) = parse_map_arg(".env.production=production").unwrap();
        assert_eq!(file, Path::new(".env.production"));
        assert_eq!(env.as_str(), "production");
        assert!(parse_map_arg("no-equals").is_err());
        assert!(parse_map_arg("=prod").is_err());
    }

    #[test]
    fn build_sources_map_overrides_rather_than_doubles() {
        let base = EnvName::parse("base").unwrap();
        let sources = build_sources(&base, Path::new(".env"), &[".env=prod".to_owned()]).unwrap();
        assert_eq!(sources.len(), 1, "same file must not become two sources");
        assert_eq!(sources[0].0, PathBuf::from(".env"));
        assert_eq!(sources[0].1.as_str(), "prod");

        // A map for a DIFFERENT file still appends; repeated maps last-win.
        let sources = build_sources(
            &base,
            Path::new(".env"),
            &[
                ".env.local=dev".to_owned(),
                ".env=staging".to_owned(),
                ".env.local=prod".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(
            sources[0],
            (PathBuf::from(".env"), EnvName::parse("staging").unwrap())
        );
        assert_eq!(
            sources[1],
            (PathBuf::from(".env.local"), EnvName::parse("prod").unwrap())
        );
    }

    /// Planning through the seam the app uses must list each entry exactly
    /// once — the doubled plan is the exact regression this guards.
    #[test]
    fn plan_via_self_map_lists_each_entry_once() {
        let base = EnvName::parse("base").unwrap();
        let sources = build_sources(&base, Path::new(".env"), &[".env=base".to_owned()]).unwrap();
        let with_text: Vec<(String, String, String)> = sources
            .iter()
            .map(|(file, env)| {
                (
                    file.display().to_string(),
                    env.as_str().to_owned(),
                    "PORT=8080\nFOO=1\nFOO=2\n".to_owned(),
                )
            })
            .collect();
        let (entries, duplicates) = plan_from_texts(&with_text).unwrap();
        assert_eq!(
            entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["PORT", "FOO"]
        );
        assert_eq!(duplicates.len(), 1);
    }

    #[test]
    fn duplicate_names_recovered_across_last_wins_parsing() {
        let dups = find_duplicate_names("A=1\nB=2\nA=3\n");
        assert_eq!(dups, vec![("A".to_owned(), vec![1, 3])]);
        assert!(find_duplicate_names("A=1\nB=2\n").is_empty());
        // KEY=-shaped text INSIDE a multiline quoted value is not an
        // assignment and must not be reported.
        let dups = find_duplicate_names("CERT=\"line1\nFAKE=inside\nend\"\nA=1\n");
        assert!(dups.is_empty());
    }

    #[test]
    fn decisions_parser_accepts_the_spec_example() {
        let text = "\
# envholster import decisions v1
version 1
plan 0000000000000000000000000000000000000000000000000000000000000000
cleanup delete_sources=yes gitignore=yes
decide .env DATABASE_URL secret 2
decide .env PORT var
decide .env LEGACY_JUNK skip
";
        let decisions = parse_decisions(text).unwrap();
        assert!(decisions.delete_sources);
        assert!(decisions.gitignore);
        assert_eq!(decisions.decide.len(), 3);
        assert_eq!(
            decisions.decide[&(".env".to_owned(), "DATABASE_URL".to_owned())],
            DecisionAction::Secret(2)
        );
        assert_eq!(
            decisions.decide[&(".env".to_owned(), "PORT".to_owned())],
            DecisionAction::Var
        );
        assert_eq!(
            decisions.decide[&(".env".to_owned(), "LEGACY_JUNK".to_owned())],
            DecisionAction::Skip
        );
    }

    #[test]
    fn decisions_parser_rejects_each_malformation_with_the_stable_code() {
        let cases = [
            // missing cleanup line entirely
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ndecide .env A var\n",
            // missing plan line entirely
            "version 1\ncleanup delete_sources=no gitignore=no\ndecide .env A var\n",
            // malformed plan digest
            "version 1\nplan abc\ncleanup delete_sources=no gitignore=no\n",
            // cleanup missing one required key
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=yes\ndecide .env A var\n",
            // bad tier
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=no gitignore=no\ndecide .env A secret 4\n",
            // duplicate decide for one (file, name)
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=no gitignore=no\ndecide .env A var\n\
             decide .env A skip\n",
            // unknown directive
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=no gitignore=no\nfrobnicate .env A\n",
            // wrong/missing version
            "version 2\ncleanup delete_sources=no gitignore=no\n",
            "cleanup delete_sources=no gitignore=no\n",
            // non-boolean cleanup value
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=maybe gitignore=no\n",
            // duplicate cleanup line
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=no gitignore=no\n\
             cleanup delete_sources=no gitignore=no\n",
        ];
        for text in cases {
            let err = parse_decisions(text).expect_err(text);
            assert_eq!(err.code, "IMPORT_DECISIONS_INVALID", "for {text:?}");
            assert_eq!(err.exit, 2, "for {text:?}");
        }
    }

    /// The line `--plan` prints is exactly what the parser accepts.
    #[test]
    fn plan_line_round_trips_through_the_parser() {
        let digest = plan_digest(
            b"k",
            &[(".env".to_owned(), "base".to_owned(), "A=1\n".to_owned())],
        );
        let text = format!(
            "version 1\n{}\ncleanup delete_sources=no gitignore=no\n",
            plan_line(&digest)
        );
        let decisions = parse_decisions(&text).unwrap();
        assert_eq!(decisions.plan_digest, digest);
    }

    #[test]
    fn exact_cover_distinguishes_stale_from_missing() {
        let decisions = parse_decisions(
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=no gitignore=no\ndecide .env GONE var\n",
        )
        .unwrap();
        let entries = vec![(".env".to_owned(), "PRESENT".to_owned())];
        let err = check_cover(&entries, &decisions).unwrap_err();
        assert_eq!(err.code, "IMPORT_PLAN_STALE");
        assert!(err.message.contains(".env:GONE"));
        assert!(err.message.contains(".env:PRESENT"));

        let decisions =
            parse_decisions("version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=no gitignore=no\n").unwrap();
        let err = check_cover(&entries, &decisions).unwrap_err();
        assert_eq!(err.code, "IMPORT_DECISION_MISSING");
        assert!(err.message.contains(".env:PRESENT"));

        let decisions = parse_decisions(
            "version 1\nplan 0000000000000000000000000000000000000000000000000000000000000000\ncleanup delete_sources=no gitignore=no\ndecide .env PRESENT skip\n",
        )
        .unwrap();
        assert!(check_cover(&entries, &decisions).is_ok());
    }

    #[test]
    fn dotenv_like_matches_the_frozen_detect_globs() {
        for name in [".env", ".env.local", ".env.production", "worker.env"] {
            assert!(dotenv_like(name), "{name}");
        }
        for name in [".envrc", "envholster.toml", "env", "secrets.holster"] {
            assert!(!dotenv_like(name), "{name}");
        }
    }

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "envholster-importcmd-test-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The D11 refusal must land BEFORE any write: after a tier-2 apply
    /// against a vault with no hardware recipient, the vault and manifest
    /// bytes are untouched and the source file survives even with
    /// `delete_sources=yes`.
    #[test]
    fn apply_refuses_tier2_without_hardware_before_any_write() {
        use std::sync::Arc;

        use envholster_core::constants::{MANIFEST_FILENAME, VAULT_FILENAME};
        use envholster_core::{
            Enrollment, EnvSelector, RecipientClass, RecipientEntry, WrapContext,
        };

        let dir = temp_dir();
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let vault_path = dir.join(VAULT_FILENAME);
        store_manifest(&manifest_path, &crate::manifestio::empty_manifest()).unwrap();
        let recovery_pub = age::x25519::Identity::generate().to_public().to_string();
        let recovery = RecipientEntry::from_encoded(
            &recovery_pub,
            RecipientClass::Recovery,
            "test-recovery".to_owned(),
            Enrollment(EnvSelector::All {
                max_tier: Tier::Critical,
            }),
        )
        .unwrap();
        let ctx = WrapContext::new(Arc::new(crate::context::CliUi));
        drop(Vault::create(&vault_path, vec![recovery], &ctx).unwrap());

        let env_path = dir.join(".env");
        std::fs::write(&env_path, "DATABASE_URL=postgres://u:p@h/db\n").unwrap();
        let decisions_path = dir.join("decisions.txt");
        std::fs::write(
            &decisions_path,
            format!(
                "version 1\nplan {}\ncleanup delete_sources=yes gitignore=yes\n\
                 decide {} DATABASE_URL secret 2\n",
                plan_key().unwrap().with_exposed(|k| plan_digest(
                    k,
                    &[(
                        env_path.display().to_string(),
                        "base".to_owned(),
                        "DATABASE_URL=postgres://u:p@h/db\n".to_owned(),
                    )],
                )),
                env_path.display()
            ),
        )
        .unwrap();

        let vault_before = std::fs::read(&vault_path).unwrap();
        let manifest_before = std::fs::read(&manifest_path).unwrap();

        let project = Project {
            root: dir.clone(),
            manifest_path: manifest_path.clone(),
            vault_path: vault_path.clone(),
        };
        let mut session = Session::new(&None, &None).unwrap();
        let err = apply_in(
            &mut session,
            &project,
            &env_path,
            &[],
            &decisions_path,
            true,
            &ImportOptions::default(),
        )
        .expect_err("tier 2 with no hardware recipient must refuse");
        assert_eq!(err.code, "DENIED");

        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before);
        assert_eq!(std::fs::read(&manifest_path).unwrap(), manifest_before);
        assert!(env_path.is_file(), "cleanup must not run after a refusal");
        assert!(
            !dir.join(".gitignore").exists(),
            "gitignore cleanup must not run after a refusal"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A duplicated name refuses apply UNLESS its decision is `skip`: skipped
    /// duplicates are unambiguous and must import the rest of the file; any
    /// other decision for the duplicated name still refuses.
    #[test]
    fn apply_allows_duplicates_only_when_skipped() {
        use std::sync::Arc;

        use envholster_core::constants::{MANIFEST_FILENAME, VAULT_FILENAME};
        use envholster_core::{
            Enrollment, EnvSelector, RecipientClass, RecipientEntry, WrapContext,
        };

        let dir = temp_dir();
        let manifest_path = dir.join(MANIFEST_FILENAME);
        let vault_path = dir.join(VAULT_FILENAME);
        store_manifest(&manifest_path, &crate::manifestio::empty_manifest()).unwrap();
        let recovery_pub = age::x25519::Identity::generate().to_public().to_string();
        let recovery = RecipientEntry::from_encoded(
            &recovery_pub,
            RecipientClass::Recovery,
            "test-recovery".to_owned(),
            Enrollment(EnvSelector::All {
                max_tier: Tier::Critical,
            }),
        )
        .unwrap();
        let ctx = WrapContext::new(Arc::new(crate::context::CliUi));
        drop(Vault::create(&vault_path, vec![recovery], &ctx).unwrap());

        let env_path = dir.join(".env");
        std::fs::write(&env_path, "FOO=1\nFOO=2\nPORT=8080\n").unwrap();
        let digest = plan_key().unwrap().with_exposed(|k| {
            plan_digest(
                k,
                &[(
                    env_path.display().to_string(),
                    "base".to_owned(),
                    "FOO=1\nFOO=2\nPORT=8080\n".to_owned(),
                )],
            )
        });
        let project = Project {
            root: dir.clone(),
            manifest_path: manifest_path.clone(),
            vault_path: vault_path.clone(),
        };

        // FOO decided var: the duplicate is ambiguous — still refuses.
        let decisions_path = dir.join("decisions-var.txt");
        std::fs::write(
            &decisions_path,
            format!(
                "version 1\nplan {digest}\ncleanup delete_sources=no gitignore=no\n\
                 decide {file} FOO var\ndecide {file} PORT var\n",
                file = env_path.display()
            ),
        )
        .unwrap();
        let mut session = Session::new(&None, &None).unwrap();
        let err = apply_in(
            &mut session,
            &project,
            &env_path,
            &[],
            &decisions_path,
            true,
            &ImportOptions::default(),
        )
        .expect_err("a duplicated name decided var must refuse");
        assert_eq!(err.code, "IMPORT_DUPLICATE_NAME");

        // FOO decided skip: unambiguous — the rest of the file imports.
        let decisions_path = dir.join("decisions-skip.txt");
        std::fs::write(
            &decisions_path,
            format!(
                "version 1\nplan {digest}\ncleanup delete_sources=no gitignore=no\n\
                 decide {file} FOO skip\ndecide {file} PORT var\n",
                file = env_path.display()
            ),
        )
        .unwrap();
        let mut session = Session::new(&None, &None).unwrap();
        apply_in(
            &mut session,
            &project,
            &env_path,
            &[],
            &decisions_path,
            true,
            &ImportOptions::default(),
        )
        .expect("a skipped duplicate must not block the import");
        let manifest = load_manifest(&manifest_path).unwrap();
        assert_eq!(manifest.vars.get("PORT").map(String::as_str), Some("8080"));
        assert!(
            !manifest.vars.contains_key("FOO"),
            "the skipped duplicate must not be written"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_result_json_shape() {
        let outcome = WriteOutcome {
            added: 3,
            updated: 1,
            brokered: vec!["OPENAI_API_KEY".to_owned()],
        };
        let json = render_apply_json(
            &outcome,
            2,
            1,
            &[".env".to_owned()],
            true,
            &[".env.production".to_owned()],
        );
        assert!(json.starts_with(
            "{\"schema\":1,\"added\":3,\"updated\":1,\"vars\":2,\"skipped\":1,\
             \"deleted_sources\":[\".env\"],\"gitignore_updated\":true,\"warning\":"
        ));
        assert!(json.contains("history exposure"));
        assert!(json.ends_with(
            ",\"brokered\":[\"OPENAI_API_KEY\"],\"uncovered_sources\":[\".env.production\"]}"
        ));
        let covered = render_apply_json(&outcome, 2, 1, &[], true, &[]);
        assert!(covered.ends_with(",\"uncovered_sources\":[]}"));
    }

    /// A recognized high-value key is proposed as a confident TIER-1 secret —
    /// never approval-gated by default (that posture is an explicit
    /// `approval-gated` decision, which the renderer still expresses
    /// additively as `declared_tier`). Accepting the plan as proposed must
    /// never leave a `run` waiting on a hardware tap. The plan contract is
    /// unchanged: names, lines, and value LENGTHS only — never values.
    #[test]
    fn plan_json_proposes_tier1_for_high_value_prefixes_never_approval_gated() {
        let text = "OPENAI_API_KEY=sk-proj-abc123\n";
        let sources = vec![(".env".to_owned(), "base".to_owned(), text.to_owned())];
        let (entries, duplicates) = plan_from_texts(&sources).unwrap();
        let json = render_plan_json(
            &[(".env".to_owned(), "base".to_owned())],
            &entries,
            &duplicates,
            "digest-under-test",
        );
        assert!(
            json.contains("\"suggestion\":{\"kind\":\"secret\",\"tier\":1,\"confident\":true}"),
            "{json}"
        );
        assert!(
            !json.contains("declared_tier"),
            "nothing is approval-gated by default: {json}"
        );
        assert!(!json.contains("sk-proj"), "plan JSON leaked value bytes");
    }
}
