//! `run -- <cmd>` — assemble the environment in-process and start the command.
//!
//! Vars come from `envholster.toml` (`[vars]`, then the selected env's, then
//! `envholster.local.toml`); secrets come from the cells this process can
//! unlock; `${NAME}` references are expanded across the final set the way
//! dotenv-expand or Next.js would have read the original file. Everything is
//! delivered in the child's environment. `--dotenv` additionally writes the
//! same set to a temporary 0600 file for tools that read a file rather than
//! the environment, and deletes it when the command exits.
//!
//! Normal shutdown signals are forwarded to the child process group. Temporary
//! plaintext is removed after the direct child exits. SIGKILL and power loss require `doctor`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use envholster_core::expand::{expand, has_reference};
use envholster_core::{EnvName, VarValue};
use envholster_mem::{process::ProcessSignals, SecretBytes};
use zeroize::Zeroizing;

use crate::commands::{find_secret_cell, unlock_ambient_cells};
use crate::context::{
    config_dir, create_secret_dir, discover_project, open_vault, write_secret_file_exclusive,
    Session,
};
use crate::errors::CliError;
use crate::exec::{self, filter_parent_env, InjectedEnv, RunRequest};
use crate::manifestio::{load_local, load_manifest};
use crate::materialize::materialize;

/// First line of every `--dotenv` file; `doctor` looks for it to report a
/// leftover from a signalled run.
pub const DOTENV_MARKER: &str =
    "# envholster run --dotenv: temporary, deleted when the command exits";

pub fn run(
    session: &mut Session,
    dotenv: Option<Option<PathBuf>>,
    cmd: &[String],
) -> Result<i32, CliError> {
    let (program, args) = cmd.split_first().ok_or_else(|| {
        CliError::parse(
            "run needs a command after --",
            Some("envholster run -- npm run dev".to_owned()),
        )
    })?;
    let project = discover_project()?;
    let manifest = load_manifest(&project.manifest_path)?;
    let local = load_local(&project)?;
    let mut vault = open_vault(&project)?;
    unlock_ambient_cells(&mut vault, session);

    let selected = session.env.clone();
    let base = EnvName::base();
    let env_opt = if selected == base {
        None
    } else {
        Some(selected.clone())
    };

    // Which secrets this env gets: every DECLARED name governing the
    // selected env (or base). The declaration is the contract every door
    // reads (`get`, `export`, the alias-collision check): a record stored
    // without one is not delivered anywhere, and `doctor` names it
    // (value-but-undeclared) so it gets declared or removed.
    let mut names: Vec<String> = Vec::new();
    for decl in &manifest.secrets {
        let governs = manifest.secret_decl(&decl.name, &selected).is_some()
            || manifest.secret_decl(&decl.name, &base).is_some();
        if governs && !names.contains(&decl.name) {
            names.push(decl.name.clone());
        }
    }

    // Secret values as text, keyed by the env var they are delivered as.
    // Zeroized on drop; `run` is the one door where plaintext is the point.
    let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    // The same values under their vault (canonical) names: `${secret:NAME}`
    // composites reference the record name, not the delivery alias a
    // declaration's `env_var` may give it.
    let mut canonical: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    let mut deny: BTreeSet<String> = names.iter().cloned().collect();
    for name in &names {
        let cell = find_secret_cell(&mut vault, session, &manifest, name)?;
        let record = vault.get_secret(&cell, name).map_err(CliError::from)?;
        let text = record
            .value
            .with_exposed(|b| std::str::from_utf8(b).map(|s| Zeroizing::new(s.to_owned())))
            .map_err(|_| {
                CliError::parse(
                    format!(
                        "secret {name:?} holds non-UTF-8 bytes and cannot be delivered as an \
                         environment value"
                    ),
                    None,
                )
            })?;
        let key = manifest.delivery_name(name, &selected);
        deny.insert(key.clone());
        canonical.insert(name.clone(), text.clone());
        secrets.insert(key, text);
    }
    // The command needs only this snapshot. Keeping Vault alive would hold
    // its exclusive lock and decrypted records throughout a dev server's life.
    drop(vault);
    let by_name = |n: &str| canonical.get(n).map(|v| v.to_string());

    // Vars: base → env → local. One unresolvable `${X}` must not sink the
    // whole run: fall back to the raw layers and let the lenient expander
    // below leave that reference as written. Said once, never silently.
    // An undeclared env is NOT leniency material: a typo'd `--env prod`
    // silently delivering the base credentials to a real command is exactly
    // the failure this tool exists to prevent.
    let vars = match manifest.resolve_vars(env_opt.as_ref(), local.as_ref()) {
        Ok(v) => v,
        Err(e @ envholster_core::ManifestError::UndeclaredEnvironment { .. }) => {
            return Err(crate::commands::undeclared_env_error(e, &manifest));
        }
        Err(e) => {
            eprintln!(
                "note: [vars] delivered partly unresolved ({e}); an unresolvable ${{...}} \
                 reference is left as written"
            );
            // Per-var fallback: only the vars touched by the bad reference
            // degrade to their raw text — a valid `${secret:...}` composite
            // elsewhere still materializes below instead of reaching the
            // child as a literal template.
            manifest.resolve_vars_lenient(env_opt.as_ref(), local.as_ref())
        }
    };
    let mut plain: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for (name, value) in vars {
        if secrets.contains_key(&name) {
            continue; // a secret wins a name collision (plan/02 §12)
        }
        let text = match value {
            VarValue::Plain(v) => v,
            // A composite carries a secret: it is secret material from here.
            VarValue::Composite { template, .. } => materialize(&template, &by_name)?,
        };
        plain.insert(name, Zeroizing::new(text));
    }
    drop(canonical);

    // The deny list applies to the FINAL environment, not only the shell's:
    // a repository's envholster.toml (or a secret named for a loader hook)
    // must not be able to load code into the secret-bearing child. Checked
    // before anything is written, so a --dotenv file never carries it either.
    if let Some(name) = plain
        .keys()
        .chain(secrets.keys())
        .find(|k| exec::is_forbidden_delivery_name(k))
    {
        return Err(CliError::denied(
            format!(
                "refusing to deliver {name}: loader hooks (DYLD_*, LD_*) and the envholster \
                 identity variables cannot be set from the project"
            ),
            Some(format!(
                "remove {name} from envholster.toml [vars], or from the vault: envholster rm {name}"
            )),
        ));
    }

    // `${NAME}` expansion over the whole delivered set, secrets included. The
    // snapshot and every pre-expansion buffer are zeroized on drop.
    let snapshot: BTreeMap<String, Zeroizing<String>> = plain
        .iter()
        .chain(secrets.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let lookup = |n: &str| snapshot.get(n).map(|v| v.to_string());
    for value in plain.values_mut().chain(secrets.values_mut()) {
        if has_reference(value) {
            *value = Zeroizing::new(expand(value, &lookup));
        }
    }
    drop(snapshot);

    // The child's base environment: this shell's, minus the deny list, with
    // the manifest's vars replacing any same-named shell value. An entry
    // that is not valid UTF-8 cannot be represented here; it is left out and
    // named, never a panic.
    let mut parent: Vec<(String, String)> = Vec::new();
    let mut not_utf8: Vec<String> = Vec::new();
    for (k, v) in std::env::vars_os() {
        match (k.into_string(), v.into_string()) {
            (Ok(k), Ok(v)) => parent.push((k, v)),
            (Ok(k), Err(_)) => not_utf8.push(k),
            (Err(k), _) => not_utf8.push(k.to_string_lossy().into_owned()),
        }
    }
    if !not_utf8.is_empty() {
        eprintln!(
            "note: not passed to the command (not valid UTF-8): {}",
            not_utf8.join(", ")
        );
    }
    let mut base_env = filter_parent_env(parent, &deny);
    base_env.retain(|(k, _)| !plain.contains_key(k));
    for (k, v) in &plain {
        base_env.push((k.clone(), v.to_string()));
    }
    let mut injected: Vec<InjectedEnv> = Vec::with_capacity(secrets.len());
    for (k, v) in &secrets {
        let value = SecretBytes::try_from_slice(v.as_bytes())
            .map_err(|e| CliError::failure(format!("locked allocation failed: {e}"), None))?;
        injected.push(InjectedEnv {
            name: k.clone(),
            value,
        });
    }

    let mut signals = ProcessSignals::install()?;
    let dotenv_guard = match dotenv {
        None => None,
        Some(explicit) => {
            let path = explicit.unwrap_or_else(|| project.root.join(".env"));
            Some(write_dotenv_file(&project.root, &path, &secrets, &plain)?)
        }
    };
    drop(plain);
    drop(secrets);

    if let Some(signal) = signals.take_pending().first() {
        return Ok(128 + signal);
    }
    let handle = exec::run(RunRequest {
        program: program.clone(),
        args: args.to_vec(),
        base_env,
        injected,
    })
    .map_err(|e| match e {
        exec::ExecError::Spawn(ref detail) if detail.contains("ENOENT") => CliError::not_found(
            format!("command not found: {program}"),
            Some("check the command name and your PATH".to_owned()),
        ),
        other => CliError::failure(format!("run: {other}"), None),
    })?;
    if !handle.shadowed_by_injection.is_empty() {
        eprintln!(
            "note: the vault's value replaced your shell's for: {}",
            handle.shadowed_by_injection.join(", ")
        );
    }
    if let Err(error) = signals.foreground_child(handle.child_pid) {
        // Do not orphan a secret-bearing process if terminal setup fails.
        ProcessSignals::abort_child(handle.child_pid);
        let _ = exec::wait(handle.child_pid, Some(&mut signals));
        return Err(CliError::failure(format!("terminal setup: {error}"), None));
    }
    let code = match exec::wait(handle.child_pid, Some(&mut signals)) {
        Ok(code) => code,
        Err(error) => {
            ProcessSignals::abort_child(handle.child_pid);
            let _ = exec::wait(handle.child_pid, None);
            return Err(CliError::failure(format!("run: {error}"), None));
        }
    };
    drop(dotenv_guard);
    Ok(code)
}

/// Deletes the `--dotenv` file on every return path of `run` (a panic
/// included; a signalled death is the documented exception), and puts the
/// import breadcrumb back when the file replaced one.
#[derive(Debug)]
struct DotenvGuard {
    path: PathBuf,
    restore_breadcrumb: bool,
    /// The in-flight record `doctor` reads after a signalled death.
    record: Option<PathBuf>,
    // Never unlink an advisory lock: another opener may still hold its inode.
    _path_lock: std::fs::File,
}

impl Drop for DotenvGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if self.restore_breadcrumb {
            let _ = std::fs::write(&self.path, crate::commands::importcmd::ENV_BREADCRUMB);
        }
        if let Some(record) = &self.record {
            let _ = std::fs::remove_file(record);
        }
    }
}

/// Where a running `--dotenv` notes the file it wrote, so `doctor` can find
/// a leftover at ANY path after a signalled death (Drop never ran). One
/// record per target path, named by the path's hash, holding the path and
/// the writing process's pid (so a file still in use is not called a
/// leftover).
fn inflight_dir() -> PathBuf {
    config_dir().join("dotenv-inflight")
}

fn note_inflight(path: &Path) -> Option<PathBuf> {
    let abs = path.canonicalize().ok()?;
    let dir = inflight_dir();
    create_secret_dir(&dir).ok()?;
    let record = dir.join(envholster_core::sha256_hex_lower(
        abs.to_string_lossy().as_bytes(),
    ));
    let _ = std::fs::remove_file(&record);
    let body = format!("{}\n{}\n", abs.to_string_lossy(), std::process::id());
    write_secret_file_exclusive(&record, body.as_bytes()).ok()?;
    Some(record)
}

/// One in-flight record: the file a run wrote and the pid that wrote it.
pub struct InflightDotenv {
    pub record: PathBuf,
    pub target: PathBuf,
    pub pid: Option<u32>,
}

impl InflightDotenv {
    /// Is the writing process still alive, and still envholster? The pid
    /// alone is not enough: the OS recycles pids, and a recycled one would
    /// turn a real leftover into "in use". `ps` naming the command settles it
    /// without a new dependency. An unknown pid (old record shape) counts as
    /// gone.
    pub fn writer_alive(&self) -> bool {
        let Some(pid) = self.pid else {
            return false;
        };
        std::process::Command::new("ps")
            .args(["-o", "comm=", "-p", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some_and(|o| String::from_utf8_lossy(&o.stdout).contains("envholster"))
    }
}

/// Every record a run noted and never cleared. `doctor` reports the targets
/// that still carry the marker and drops the rest.
pub fn inflight_dotenv_paths() -> Vec<InflightDotenv> {
    let Ok(entries) = std::fs::read_dir(inflight_dir()) else {
        return Vec::new();
    };
    let mut out: Vec<InflightDotenv> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter_map(|record| {
            let body = std::fs::read_to_string(&record).ok()?;
            let mut lines = body.lines();
            let target = PathBuf::from(lines.next()?.trim());
            let pid = lines.next().and_then(|l| l.trim().parse::<u32>().ok());
            Some(InflightDotenv {
                record,
                target,
                pid,
            })
        })
        .collect();
    out.sort_by(|a, b| a.record.cmp(&b.record));
    out
}

/// Does `<root>/.gitignore` keep a `.env` file out of git? Exact rules only
/// (`.env`, `/.env`, `.env*`, `*.env`, `**/.env`): a fancier pattern that
/// happens to match is not evidence the author meant it.
pub fn gitignore_covers_dotenv(root: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(root.join(".gitignore")) else {
        return false;
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.strip_prefix('/').unwrap_or(l))
        .any(|l| matches!(l, ".env" | ".env*" | "*.env" | "**/.env"))
}

/// Is `path` kept out of git? `git check-ignore` is the effective evaluation
/// — nested .gitignore files, negations, the requested path rather than a
/// nominal `.env` — so it is asked first. Deliberately WITHOUT `--no-index`:
/// a file that is force-tracked despite matching an ignore rule is reported
/// as not ignored, which is the truth that matters here (a `git commit -a`
/// during the run would stage it). When git cannot answer (no
/// git binary, not a repository, exit 128), fall back to reading
/// `<root>/.gitignore` with the exact frozen rules against the file's name.
pub(super) fn dotenv_path_is_ignored(root: &Path, path: &Path) -> bool {
    let abs = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_owned())
    };
    let from = abs
        .parent()
        .filter(|p| p.is_dir())
        .unwrap_or(root)
        .to_owned();
    let answer = std::process::Command::new("git")
        .current_dir(&from)
        .args(["check-ignore", "-q", "--"])
        .arg(&abs)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
        .and_then(|s| match s.code() {
            Some(0) => Some(true),
            Some(1) => Some(false),
            _ => None,
        });
    answer.unwrap_or_else(|| {
        let name = abs.file_name().and_then(|n| n.to_str()).unwrap_or("");
        gitignore_rule_covers(root, name)
    })
}

/// Is `path` in git's index? A tracked file is what `git commit -a` would
/// stage, whatever the ignore rules say.
pub(crate) fn git_tracks(root: &Path, path: &Path) -> bool {
    let abs = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_owned())
    };
    std::process::Command::new("git")
        .current_dir(root)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(&abs)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The no-git fallback: does `<root>/.gitignore` cover `name`? Exact rule
/// shapes only (`.env`, `/.env`, `**/.env`, `.env*`, `*.env`, or the file's
/// own literal name), evaluated in order with `!` negation the way git would
/// — a fancier pattern that happens to match is not evidence the author meant
/// it. The literal-name shape is what makes `!.env.production` count: an
/// import must not treat an earlier `.env*` as coverage the author revoked.
fn gitignore_rule_covers(root: &Path, name: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(root.join(".gitignore")) else {
        return false;
    };
    let mut ignored = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (pattern, negated) = match line.strip_prefix('!') {
            Some(rest) => (rest, true),
            None => (line, false),
        };
        let pattern = pattern.strip_prefix("**/").unwrap_or(pattern);
        let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
        let matches = match pattern {
            ".env" => name == ".env",
            ".env*" => name.starts_with(".env"),
            "*.env" => name.ends_with(".env"),
            "*.envholster.lock" => name.ends_with(".envholster.lock"),
            literal if !literal.contains(['*', '?', '[', '/']) => name == literal,
            _ => false,
        };
        if matches {
            ignored = !negated;
        }
    }
    ignored
}

fn write_dotenv_file(
    root: &Path,
    path: &Path,
    secrets: &BTreeMap<String, Zeroizing<String>>,
    vars: &BTreeMap<String, Zeroizing<String>>,
) -> Result<DotenvGuard, CliError> {
    // A value no dotenv reader encodes unambiguously is refused before any
    // other check: a wrong secret read from the file fails far from here.
    if let Some((name, reason)) = secrets
        .iter()
        .chain(vars.iter())
        .find_map(|(k, v)| envholster_core::dotenv::readers_disagree_reason(v).map(|r| (k, r)))
    {
        return Err(crate::commands::dotenv_unencodable(
            name,
            reason,
            "drop --dotenv (the environment still carries it), or change the value",
        ));
    }
    // Refusals must not litter a project with a new persistent lock file.
    check_dotenv_destination(root, path)?;
    // Serialize only this dotenv path. Other runs and vault edits remain free.
    // Canonicalizing its directory makes relative spellings share one lock.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let filename = path
        .file_name()
        .ok_or_else(|| CliError::parse("--dotenv needs a file path", None))?;
    let lock_path = parent
        .canonicalize()?
        .join(format!("{}.envholster.lock", filename.to_string_lossy()));
    let path_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    path_lock.try_lock().map_err(|_| {
        CliError::failure(
            format!(
                "{} is in use by another `envholster run --dotenv`",
                path.display()
            ),
            Some("wait for that command to exit, or pass --dotenv <other path>".to_owned()),
        )
    })?;
    // Repeat the preflight while holding the lock: another run may have
    // created or replaced the destination since the first inspection.
    let restore_breadcrumb = check_dotenv_destination(root, path)?;
    if !dotenv_path_is_ignored(root, &lock_path) {
        eprintln!("note: add '*.envholster.lock' to .gitignore to ignore dotenv lock sidecars, including custom paths");
    }
    // Secrets and vars go through the ONE dotenv writer, so a file consumer
    // parses back exactly the values the child's environment carries — a
    // value with a space, a `#`, quotes, or padding must not silently differ
    // between the two delivery doors. Worst-case capacity (every char
    // escaping to two, plus framing) is reserved up front so pushes never
    // reallocate and leave an unzeroized fragment behind.
    let reserve: usize = secrets
        .iter()
        .chain(vars.iter())
        .map(|(k, v)| k.len() + 2 * v.len() + 4)
        .sum();
    let mut content: Zeroizing<String> = Zeroizing::new(String::new());
    content.reserve(DOTENV_MARKER.len() + 1 + reserve);
    content.push_str(DOTENV_MARKER);
    content.push('\n');
    for (k, v) in secrets {
        envholster_core::dotenv::write_dotenv_line(&mut content, k, v);
    }
    for (k, v) in vars {
        envholster_core::dotenv::write_dotenv_line(&mut content, k, v);
    }
    if restore_breadcrumb {
        std::fs::remove_file(path)?;
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(error) => {
            if restore_breadcrumb {
                let _ = write_secret_file_exclusive(
                    path,
                    crate::commands::importcmd::ENV_BREADCRUMB.as_bytes(),
                );
            }
            return Err(error.into());
        }
    };
    // Ownership starts only after create_new succeeds; partial writes still clean up.
    let mut guard = DotenvGuard {
        path: path.to_owned(),
        restore_breadcrumb,
        record: None,
        _path_lock: path_lock,
    };
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    guard.record = note_inflight(path);
    disclose_once(path);
    Ok(guard)
}

fn check_dotenv_destination(root: &Path, path: &Path) -> Result<bool, CliError> {
    // The one existing file --dotenv may replace is import's comment-only
    // breadcrumb (restored on exit); anything else is refused untouched.
    // The WHOLE file must match the breadcrumb: the exit path restores the
    // constant, so a breadcrumb a tool appended to (`prisma init` adding
    // DATABASE_URL) carries user content that restore would destroy.
    let restore_breadcrumb = if path.symlink_metadata().is_ok() {
        let existing = std::fs::read_to_string(path).ok().map(Zeroizing::new);
        // Our own leftover (a signalled earlier run) holds plaintext secrets:
        // say so and name the remedy, never "move it aside".
        if existing
            .as_deref()
            .is_some_and(|t| t.lines().next() == Some(DOTENV_MARKER))
        {
            // Still owned by a live run? Then it is not a leftover, and the
            // remedy is to wait, not to delete a file its child is reading.
            let canonical = path.canonicalize().unwrap_or_else(|_| path.to_owned());
            if let Some(live) = inflight_dotenv_paths().into_iter().find(|i| {
                i.target.canonicalize().unwrap_or_else(|_| i.target.clone()) == canonical
                    && i.writer_alive()
            }) {
                return Err(CliError::failure(
                    format!(
                        "{} is in use by another `envholster run --dotenv` (pid {})",
                        path.display(),
                        live.pid.unwrap_or(0)
                    ),
                    Some("wait for that command to exit, or pass --dotenv <other path>".to_owned()),
                ));
            }
            return Err(CliError::failure(
                format!(
                    "{} was left behind by an earlier run --dotenv that did not exit cleanly; it \
                     holds plaintext secrets",
                    path.display()
                ),
                Some(format!("rm {}", path.display())),
            ));
        }
        if existing.as_deref().map(String::as_str)
            != Some(crate::commands::importcmd::ENV_BREADCRUMB)
        {
            return Err(CliError::failure(
                format!(
                    "refusing to overwrite an existing .env ({})",
                    path.display()
                ),
                Some("move that file aside, or pass --dotenv <other path>".to_owned()),
            ));
        }
        true
    } else {
        false
    };
    if !dotenv_path_is_ignored(root, path) {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(".env");
        if git_tracks(root, path) {
            // Ignore rules do not apply to a tracked file; the remedy is to
            // stop tracking it, not to add a rule that is already there.
            return Err(CliError::denied(
                format!(
                    "git tracks {} — a --dotenv file must never be committable",
                    path.display()
                ),
                Some(format!(
                    "git rm --cached {name}   # keep the file, stop tracking it; then commit"
                )),
            ));
        }
        let hint = if name == ".env" {
            "printf '.env\\n.env.*\\n!.env.example\\n' >> .gitignore".to_owned()
        } else {
            format!("add '{name}' and '*.envholster.lock' to .gitignore")
        };
        return Err(CliError::denied(
            format!(
                "git does not ignore {} — a --dotenv file must never be committable",
                path.display()
            ),
            Some(hint),
        ));
    }
    Ok(restore_breadcrumb)
}

/// The `--dotenv` exposure notice, printed once per machine; the empty file
/// `~/.config/envholster/dotenv-disclosed` records that it was shown.
fn disclose_once(path: &Path) {
    let dir = config_dir();
    let marker = dir.join("dotenv-disclosed");
    if marker.exists() {
        return;
    }
    eprintln!(
        "envholster: writing secrets to `{}` (mode 0600) for as long as the command runs. \
         Any process running as your user can read that file until the command exits. \
         This notice prints once.",
        path.display()
    );
    if create_secret_dir(&dir).is_ok() {
        let _ = std::fs::write(&marker, b"");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "envholster-run-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn zmap(pairs: &[(&str, &str)]) -> BTreeMap<String, Zeroizing<String>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Zeroizing::new((*v).to_owned())))
            .collect()
    }

    /// `writer_alive` must say yes for this very process (an envholster test
    /// binary, so `ps` names it) and no for a pid that cannot be ours.
    #[test]
    fn writer_alive_needs_a_live_envholster_process() {
        let mine = InflightDotenv {
            record: PathBuf::new(),
            target: PathBuf::new(),
            pid: Some(std::process::id()),
        };
        assert!(mine.writer_alive());
        let gone = InflightDotenv {
            record: PathBuf::new(),
            target: PathBuf::new(),
            pid: Some(u32::MAX - 1),
        };
        assert!(!gone.writer_alive());
        let unknown = InflightDotenv {
            record: PathBuf::new(),
            target: PathBuf::new(),
            pid: None,
        };
        assert!(!unknown.writer_alive());
    }

    #[test]
    fn gitignore_rule_detection_is_exact() {
        let dir = std::env::temp_dir().join(format!("envholster-gi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!gitignore_covers_dotenv(&dir));
        std::fs::write(dir.join(".gitignore"), "# c\nnode_modules/\n.envrc\n").unwrap();
        assert!(!gitignore_covers_dotenv(&dir));
        std::fs::write(dir.join(".gitignore"), "node_modules/\n/.env\n").unwrap();
        assert!(gitignore_covers_dotenv(&dir));
        std::fs::write(dir.join(".gitignore"), ".env*\n").unwrap();
        assert!(gitignore_covers_dotenv(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gitignore_fallback_matches_the_name_and_honors_negation() {
        let dir = temp_dir("fallback");
        std::fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        assert!(gitignore_rule_covers(&dir, ".env"));
        assert!(!gitignore_rule_covers(&dir, "custom-secrets.env"));
        std::fs::write(dir.join(".gitignore"), "*.env\n").unwrap();
        assert!(gitignore_rule_covers(&dir, "custom-secrets.env"));
        // A later negation un-ignores, the way git evaluates the file.
        std::fs::write(dir.join(".gitignore"), ".env\n!.env\n").unwrap();
        assert!(!gitignore_rule_covers(&dir, ".env"));
        std::fs::write(dir.join(".gitignore"), "!.env\n.env\n").unwrap();
        assert!(gitignore_rule_covers(&dir, ".env"));
        // A literal name is the author's clearest intent, in both directions.
        std::fs::write(dir.join(".gitignore"), "custom-secrets.env\n").unwrap();
        assert!(gitignore_rule_covers(&dir, "custom-secrets.env"));
        assert!(!gitignore_rule_covers(&dir, ".env"));
        std::fs::write(dir.join(".gitignore"), ".env*\n!.env.production\n").unwrap();
        assert!(gitignore_rule_covers(&dir, ".env"));
        assert!(!gitignore_rule_covers(&dir, ".env.production"));
        assert!(gitignore_rule_covers(&dir, ".env.production.local"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The file and the environment must carry the SAME values: every secret
    /// line goes through the quoting dotenv writer, and this crate's own
    /// parser reads back exactly what was delivered.
    #[test]
    fn dotenv_file_round_trips_values_the_environment_delivers() {
        let dir = temp_dir("quote");
        std::fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        let path = dir.join(".env");
        let secrets = zmap(&[
            ("API_KEY", "val with space # hash"),
            ("PADDED", "  padded  "),
            ("QUOTED", "\"quoted\""),
            ("MULTILINE", "line\nbreak"),
        ]);
        let vars = zmap(&[("PORT", "3000")]);
        let guard = write_dotenv_file(&dir, &path, &secrets, &vars).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(DOTENV_MARKER));
        let parsed: BTreeMap<String, String> = envholster_core::dotenv::parse_dotenv(&text)
            .unwrap()
            .into_iter()
            .map(|e| (e.name, e.value))
            .collect();
        for (k, v) in secrets.iter().chain(vars.iter()) {
            assert_eq!(
                parsed.get(k).map(String::as_str),
                Some(&***v),
                "{k} must parse back to the value the environment carries"
            );
        }
        drop(guard);
        assert!(!path.exists(), "the dotenv file must be gone after the run");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `import` leaves a comment-only breadcrumb at `.env`; the default
    /// `--dotenv` path must replace it for the child's lifetime and restore
    /// it on exit, while any OTHER existing file still refuses.
    #[test]
    fn dotenv_replaces_the_import_breadcrumb_and_restores_it() {
        let dir = temp_dir("breadcrumb");
        std::fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        let path = dir.join(".env");
        let breadcrumb = crate::commands::importcmd::ENV_BREADCRUMB;
        std::fs::write(&path, breadcrumb).unwrap();

        let secrets = zmap(&[("API_KEY", "k")]);
        let vars = zmap(&[]);
        let guard = write_dotenv_file(&dir, &path, &secrets, &vars)
            .expect("the import breadcrumb must not block run --dotenv");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(DOTENV_MARKER), "{text}");
        drop(guard);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            breadcrumb,
            "the breadcrumb must come back after the run"
        );

        // Anything that is not the breadcrumb still refuses, untouched.
        std::fs::write(&path, "KEEP=me\n").unwrap();
        let err = write_dotenv_file(&dir, &path, &secrets, &vars).unwrap_err();
        assert!(err.message.contains("refusing to overwrite"), "{err:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "KEEP=me\n");

        // A breadcrumb something appended to (`prisma init` adding
        // DATABASE_URL, a hand edit) is user content: refuse it byte for
        // byte untouched — the exit path restores the constant breadcrumb,
        // which would delete the appended lines.
        let appended = format!("{breadcrumb}DATABASE_URL=\"postgresql://localhost/db\"\n");
        std::fs::write(&path, &appended).unwrap();
        let err = write_dotenv_file(&dir, &path, &secrets, &vars).unwrap_err();
        assert!(err.message.contains("refusing to overwrite"), "{err:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), appended);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A custom `--dotenv` path is judged by git's EFFECTIVE ignore rules for
    /// that path, not by whether a nominal `.env` rule exists somewhere.
    #[test]
    fn dotenv_custom_path_must_be_ignored_by_git() {
        let dir = temp_dir("checkignore");
        let git_ready = std::process::Command::new("git")
            .current_dir(&dir)
            .arg("init")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !git_ready {
            // No usable git on this machine: the fallback matcher is covered
            // by gitignore_fallback_matches_the_name_and_honors_negation.
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        std::fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        let secrets = zmap(&[("API_KEY", "k")]);
        let vars = zmap(&[]);

        let custom = dir.join("custom-secrets.env");
        let err = write_dotenv_file(&dir, &custom, &secrets, &vars)
            .expect_err("an unignored custom path must refuse");
        assert!(err.message.contains("does not ignore"), "{err:?}");
        assert!(!custom.exists());

        std::fs::write(dir.join(".gitignore"), ".env\n*.env\n").unwrap();
        let guard = write_dotenv_file(&dir, &custom, &secrets, &vars)
            .expect("an ignored custom path must write");
        drop(guard);

        // A later negation makes even the default path committable: refuse.
        std::fs::write(dir.join(".gitignore"), ".env\n!.env\n").unwrap();
        let err = write_dotenv_file(&dir, &dir.join(".env"), &secrets, &vars)
            .expect_err("a negated .env rule must refuse");
        assert!(err.message.contains("does not ignore"), "{err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
