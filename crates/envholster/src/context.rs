//! Shared CLI context: environment resolution, project discovery, identity
//! discovery/loading, interactive prompts, and secret input.
//!
//! Frozen resolution chains (plan/04 §4.4, in code — clap's `env` feature is
//! not in the pin set):
//! - environment: `--env` → `ENVHOLSTER_ENV` → `base`
//! - identity: `--identity <path>` → `ENVHOLSTER_IDENTITY` (contents) →
//!   `ENVHOLSTER_IDENTITY_FILE` (path) → identity dir files
//!
//! Secret input (plan/03 window 8): stdin is read into a pre-sized locked
//! buffer; prompt input goes through rpassword (no echo) and the transient
//! `String` is zeroized on conversion.

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use envholster_core::constants::{
    DIR_MODE_SECRET, FILE_MODE_SECRET, MANIFEST_FILENAME, VAULT_FILENAME,
};
use envholster_core::{
    CoreError, EnvName, Identity, PluginName, RecipientKind, UnlockUi, Vault, VaultUuid,
    WrapContext,
};
use envholster_mem::SecretBytes;
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::errors::{CliError, EXIT_LOCKED};

pub const ENVVAR_ENV: &str = "ENVHOLSTER_ENV";
pub const ENVVAR_IDENTITY: &str = "ENVHOLSTER_IDENTITY";
pub const ENVVAR_IDENTITY_FILE: &str = "ENVHOLSTER_IDENTITY_FILE";

/// Hard cap on a single secret value read from stdin/prompt: the pre-sized
/// locked buffer must stay inside worst-case RLIMIT_MEMLOCK budgets
/// (plan/03 §3.5); 64 KiB covers SSH keys and certificates comfortably.
pub const MAX_SECRET_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Environment resolution
// ---------------------------------------------------------------------------

/// Pure form of the frozen chain, testable without process-global env.
pub fn resolve_env_from(flag: Option<&str>, env_var: Option<&str>) -> Result<EnvName, CliError> {
    let raw = flag.or(env_var);
    match raw {
        Some(name) => EnvName::parse(name).map_err(|e| {
            CliError::from(e).with_next(
                "environment names match [a-z0-9][a-z0-9_-]{0,31}; 'envholster status' lists the declared ones",
            )
        }),
        None => Ok(EnvName::base()),
    }
}

pub fn resolve_env(flag: &Option<String>) -> Result<EnvName, CliError> {
    let from_env = std::env::var(ENVVAR_ENV).ok();
    resolve_env_from(flag.as_deref(), from_env.as_deref())
}

// ---------------------------------------------------------------------------
// Project discovery (plan/07 §7.3: git-style walk-up, nearest wins)
// ---------------------------------------------------------------------------

pub struct Project {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub vault_path: PathBuf,
}

impl Project {
    pub fn recovery_blob_path(&self) -> PathBuf {
        recovery_blob_path(&self.vault_path)
    }

    pub fn local_override_path(&self) -> PathBuf {
        self.root.join("envholster.local.toml")
    }
}

/// The recovery blob lives beside the vault (plan/02 §7).
pub fn recovery_blob_path(vault: &Path) -> PathBuf {
    let name = vault
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_owned());
    vault.with_file_name(format!("{name}.recovery.age"))
}

pub fn discover_project() -> Result<Project, CliError> {
    let cwd = std::env::current_dir()?;
    let mut dir: &Path = &cwd;
    loop {
        let manifest = dir.join(MANIFEST_FILENAME);
        if manifest.is_file() {
            return Ok(Project {
                root: dir.to_owned(),
                manifest_path: manifest,
                vault_path: dir.join(VAULT_FILENAME),
            });
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => {
                return Err(CliError::not_found(
                    format!(
                        "no {MANIFEST_FILENAME} found walking up from {} — this directory is \
                         not an envholster project",
                        cwd.display()
                    ),
                    Some("envholster init".to_owned()),
                ))
            }
        }
    }
}

/// How long a command waits for another envholster command to release the
/// vault before reporting it busy.
///
/// Most commands hold the vault's exclusive lock for milliseconds, and `run`
/// releases it before starting the child. Without a wait, apps launched
/// together (`concurrently`, a monorepo runner) fail on a collision that
/// would have cleared almost at once. A command still holding the lock at the
/// deadline, such as `set` waiting at its prompt, is a real conflict and gets
/// the same busy error as before.
const VAULT_OPEN_WAIT: Duration = Duration::from_secs(2);
const VAULT_OPEN_POLL: Duration = Duration::from_millis(25);

/// Opens the project vault, mapping a missing file to the init hint.
pub fn open_vault(project: &Project) -> Result<Vault, CliError> {
    if !project.vault_path.is_file() {
        return Err(CliError::not_found(
            format!("vault {} does not exist", project.vault_path.display()),
            Some("envholster init".to_owned()),
        ));
    }
    open_vault_waiting(&project.vault_path, VAULT_OPEN_WAIT).map_err(CliError::from)
}

/// Core's lock stays non-blocking, so the wait lives here. Only the busy-lock
/// shape is retried; every other error, and a lock still held at the
/// deadline, surfaces unchanged so error mapping is identical to a single
/// attempt.
pub(crate) fn open_vault_waiting(path: &Path, wait: Duration) -> Result<Vault, CoreError> {
    let deadline = Instant::now() + wait;
    loop {
        match Vault::open(path) {
            Err(CoreError::Io(io))
                if io.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(VAULT_OPEN_POLL);
            }
            other => return other,
        }
    }
}

// ---------------------------------------------------------------------------
// Config / identity paths
// ---------------------------------------------------------------------------

/// `$XDG_CONFIG_HOME/envholster` else `~/.config/envholster` (plan/07 §7.3
/// names `~/.config/envholster` as the user-scoped home).
pub fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("envholster");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home).join(".config").join("envholster")
}

/// Fixed identity directory: one 0600 file per identity (plan/07 §7.6).
pub fn identities_dir() -> PathBuf {
    config_dir().join("identities")
}

/// An explicit source replaces ambient credentials so a restricted identity
/// cannot silently borrow this machine's broader access.
pub fn load_identities(flag: &Option<PathBuf>) -> Result<(Vec<Identity>, Vec<PathBuf>), CliError> {
    if let Some(path) = flag {
        return load_identity_file(path, "--identity");
    }
    if let Ok(contents) = std::env::var(ENVVAR_IDENTITY) {
        let contents = Zeroizing::new(contents);
        if !contents.trim().is_empty() {
            return Ok((parse_identity_text(&contents, ENVVAR_IDENTITY)?, Vec::new()));
        }
    }
    if let Ok(path) = std::env::var(ENVVAR_IDENTITY_FILE) {
        if !path.is_empty() {
            return load_identity_file(Path::new(&path), ENVVAR_IDENTITY_FILE);
        }
    }
    let mut identities = Vec::new();
    let mut sources = Vec::new();
    for path in identity_dir_files() {
        // Stray directory files should not disable otherwise usable keys.
        if let Ok((parsed, paths)) = load_identity_file(&path, "local identity directory") {
            identities.extend(parsed);
            sources.extend(paths);
        }
    }
    Ok((identities, sources))
}

fn load_identity_file(
    path: &Path,
    source: &str,
) -> Result<(Vec<Identity>, Vec<PathBuf>), CliError> {
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        CliError::not_found(
            format!("{source} identity file {} unreadable: {e}", path.display()),
            Some(format!("select a readable identity file in {source}")),
        )
    })?);
    Ok((
        parse_identity_text(&text, &path.display().to_string())?,
        vec![path.to_owned()],
    ))
}

pub fn identity_dir_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(identities_dir()) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Parses identity file contents: comment/blank lines skipped;
/// `AGE-SECRET-KEY-1...` → X25519, `AGE-PLUGIN-...` → plugin (allowlisted).
pub fn parse_identity_text(text: &str, source: &str) -> Result<Vec<Identity>, CliError> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_ascii_uppercase().starts_with("AGE-SECRET-KEY-1") {
            let identity = line.parse::<age::x25519::Identity>().map_err(|reason| {
                CliError::parse(format!("{source}: invalid X25519 identity: {reason}"), None)
            })?;
            out.push(Identity::X25519(identity));
        } else if line.to_ascii_uppercase().starts_with("AGE-PLUGIN-") {
            let plugin = line.parse::<age::plugin::Identity>().map_err(|reason| {
                CliError::parse(format!("{source}: invalid plugin identity: {reason}"), None)
            })?;
            let name = PluginName::parse(plugin.plugin()).map_err(CliError::from)?;
            out.push(Identity::Plugin {
                name,
                encoded: line.to_owned(),
            });
        } else {
            return Err(CliError::parse(
                format!(
                    "{source}: unrecognized identity line (expected AGE-SECRET-KEY-1... or \
                     AGE-PLUGIN-...)"
                ),
                None,
            ));
        }
    }
    if out.is_empty() {
        return Err(CliError::parse(
            format!("{source}: no identity found"),
            None,
        ));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Interactive UI (UnlockUi over stderr/stdin; rpassword for secrets)
// ---------------------------------------------------------------------------

pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

/// The CLI's `UnlockUi`: messages to stderr; prompts read from stdin —
/// terminal or scripted pipe alike (the verifier drives the ceremony over a
/// pipe). EOF answers `None`; callers surface that as the hard
/// machine-readable interactive-required error (plan/07 §7.7).
pub struct CliUi;

impl UnlockUi for CliUi {
    fn message(&self, message: &str) {
        eprintln!("{message}");
    }

    fn confirm(&self, message: &str, yes: &str, no: Option<&str>) -> Option<bool> {
        let no = no.unwrap_or("no");
        let line = read_stdin_line(&format!("{message} [{yes}/{no}]: ")).ok()??;
        let answer = line.trim().to_ascii_lowercase();
        if answer.is_empty() {
            return Some(true);
        }
        Some(answer == "y" || answer == "yes" || answer == yes.to_ascii_lowercase())
    }

    fn input(&self, description: &str) -> Option<String> {
        read_stdin_line(&format!("{description}: ")).ok()?
    }

    fn secret(&self, description: &str) -> Option<SecretString> {
        let value = read_secret_line(&format!("{description}: ")).ok()??;
        Some(SecretString::from(value))
    }
}

/// Writes `prompt` to stderr and reads one line from stdin. `Ok(None)` = EOF.
fn read_stdin_line(prompt: &str) -> std::io::Result<Option<String>> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\n', '\r']).to_owned()))
}

/// One secret line: rpassword (no echo) when stdin is a real terminal, a
/// plain stdin line when it is a pipe. `Ok(None)` = EOF.
fn read_secret_line(prompt: &str) -> std::io::Result<Option<String>> {
    if stdin_is_tty() {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        return rpassword::read_password().map(Some);
    }
    read_stdin_line(prompt)
}

/// Prompt for one non-secret line; EOF (stdin closed — headless without the
/// required flags) is the hard machine-readable error (plan/07 §7.7/§7.10).
pub fn prompt_line(prompt: &str, next: &str) -> Result<String, CliError> {
    match read_stdin_line(prompt)? {
        Some(line) => Ok(line.trim().to_owned()),
        None => Err(CliError::interactive_required("this prompt", next)),
    }
}

/// For questions with a safe default: EOF answers `None` so the caller can
/// apply the default. Coding agents and scripts run with stdin closed, and
/// failing there would turn finished work into an error.
pub fn prompt_line_or_default(prompt: &str) -> Result<Option<String>, CliError> {
    let answer = read_stdin_line(prompt)?;
    if answer.is_none() {
        // The prompt is still on the line; finish it before the next message.
        eprintln!();
    }
    Ok(answer.map(|line| line.trim().to_owned()))
}

/// No-echo secret prompt returning a locked buffer; the transient String is
/// zeroized (plan/03 window 8 residual: rpassword's own internal buffer).
pub fn prompt_secret_locked(prompt: &str) -> Result<SecretBytes, CliError> {
    let mut value = read_secret_line(prompt)?.ok_or_else(|| {
        CliError::interactive_required(
            "secret entry",
            "pipe the value instead: '... --stdin' with the value on stdin",
        )
    })?;
    let out = SecretBytes::try_from_string(&mut value)
        .map_err(|e| CliError::failure(format!("locked allocation failed: {e}"), None))?;
    Ok(out)
}

/// One secret line as a String for parse-then-discard flows (identity
/// re-entry at init); zeroize at the call site. `None` = EOF.
pub fn prompt_secret_string(prompt: &str) -> Result<Option<String>, CliError> {
    read_secret_line(prompt).map_err(CliError::from)
}

/// Reads a secret value: `--stdin` → pre-sized locked buffer, one trailing
/// newline stripped; otherwise a no-echo prompt. Never argv (plan/04 §4.4).
pub fn read_secret_value(prompt: &str, use_stdin: bool) -> Result<SecretBytes, CliError> {
    let mut value = if use_stdin {
        read_stdin_locked()?
    } else {
        prompt_secret_locked(prompt)?
    };
    // Strip exactly one trailing newline (LF or CRLF) — shell heredocs and
    // `echo` add one; a value that genuinely ends in a newline can be piped
    // with `printf` including a second one.
    let len = value.len();
    let strip = value.with_exposed(|b| {
        if b.ends_with(b"\r\n") {
            2
        } else if b.ends_with(b"\n") {
            1
        } else {
            0
        }
    });
    if strip > 0 {
        value.truncate(len - strip);
    }
    if value.is_empty() {
        return Err(CliError::parse(
            "empty secret value",
            Some("provide a non-empty value on stdin or at the prompt".to_owned()),
        ));
    }
    Ok(value)
}

/// Plan/03 window 8: stdin secret input goes straight into a pre-sized
/// locked buffer — never a growing `String`/`read_line`.
fn read_stdin_locked() -> Result<SecretBytes, CliError> {
    let mut buf = SecretBytes::try_with_capacity(MAX_SECRET_LEN)
        .map_err(|e| CliError::failure(format!("locked allocation failed: {e}"), None))?;
    let filled = buf.with_exposed_mut(|b| -> std::io::Result<usize> {
        let mut stdin = std::io::stdin().lock();
        let mut filled = 0usize;
        loop {
            let n = stdin.read(&mut b[filled..])?;
            if n == 0 {
                return Ok(filled);
            }
            filled += n;
            if filled == b.len() {
                // Distinguish exactly-full from oversized with one probe byte.
                let mut probe = [0u8; 1];
                if stdin.read(&mut probe)? == 0 {
                    return Ok(filled);
                }
                return Err(std::io::Error::other("secret value too large"));
            }
        }
    });
    match filled {
        Ok(len) => {
            buf.truncate(len);
            Ok(buf)
        }
        Err(e) if e.to_string().contains("too large") => Err(CliError::parse(
            format!("secret value exceeds the {MAX_SECRET_LEN}-byte limit"),
            None,
        )),
        Err(e) => Err(CliError::from(e)),
    }
}

// ---------------------------------------------------------------------------
// Session: identities + unlock with the scrypt re-prompt loop
// ---------------------------------------------------------------------------

pub struct Session {
    pub env: EnvName,
    pub ui: WrapContext,
    pub identities: Vec<Identity>,
    /// The global `--identity` flag, retained for flows that must
    /// re-resolve EXPLICIT identity sources only (recovery test).
    pub identity_flag: Option<PathBuf>,
    scrypt_prompted: bool,
}

impl Session {
    pub fn new(
        env_flag: &Option<String>,
        identity_flag: &Option<PathBuf>,
    ) -> Result<Self, CliError> {
        let env = resolve_env(env_flag)?;
        let (identities, _) = load_identities(identity_flag)?;
        Ok(Session {
            env,
            ui: WrapContext::new(Arc::new(CliUi)),
            identities,
            identity_flag: identity_flag.clone(),
            scrypt_prompted: false,
        })
    }

    /// A session over explicit identities, for unit tests that build their
    /// own vault instead of reading the fixed identity directory.
    #[cfg(test)]
    pub fn with_identities(env: EnvName, identities: Vec<Identity>) -> Self {
        Session {
            env,
            ui: WrapContext::new(Arc::new(CliUi)),
            identities,
            identity_flag: None,
            scrypt_prompted: false,
        }
    }

    /// Unlocks a cell, retrying once with a prompted scrypt passphrase when
    /// the vault has a scrypt recipient and we are interactive. Exhaustion is
    /// surfaced with the vault's recipient list (plan/07 §7.10).
    pub fn unlock(
        &mut self,
        vault: &mut Vault,
        cell: &envholster_core::CellId,
    ) -> Result<(), CliError> {
        loop {
            match vault.unlock_cell(cell, &self.identities, &self.ui) {
                Ok(()) => return Ok(()),
                Err(CoreError::NoMatchingIdentity {
                    env,
                    tier,
                    saw_wrong_passphrase,
                }) => {
                    let has_scrypt = vault
                        .recipients()
                        .iter()
                        .any(|r| matches!(r.kind, RecipientKind::Scrypt { .. }));
                    if has_scrypt && (!self.scrypt_prompted || saw_wrong_passphrase) {
                        let prompt = if saw_wrong_passphrase {
                            "Wrong passphrase — vault passphrase: "
                        } else {
                            "Vault passphrase: "
                        };
                        if let Ok(Some(entered)) = read_secret_line(prompt) {
                            self.identities
                                .retain(|i| !matches!(i, Identity::Scrypt(_)));
                            self.identities
                                .push(Identity::Scrypt(SecretString::from(entered)));
                            self.scrypt_prompted = true;
                            continue;
                        }
                        // EOF / unreadable stdin: fall through to the
                        // machine-actionable exhaustion error below.
                    }
                    let recipients = vault
                        .recipients()
                        .iter()
                        .map(|r| format!("{} ({:?}, {})", r.id.as_str(), r.class, r.label))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(CliError::new(
                        "NO_MATCHING_IDENTITY",
                        EXIT_LOCKED,
                        format!(
                            "no supplied identity can unwrap cell {env}:{tier} \
                             (wrong passphrase seen: {saw_wrong_passphrase}). \
                             Enrolled recipients: {recipients}"
                        ),
                        Some(
                            "supply an identity via --identity <path>, ENVHOLSTER_IDENTITY, or \
                             ENVHOLSTER_IDENTITY_FILE; to enroll this machine ask a holder to run \
                             'envholster recipient add <your age1... public key> --class software'"
                                .to_owned(),
                        ),
                    ));
                }
                Err(other) => return Err(CliError::from(other)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Misc small helpers
// ---------------------------------------------------------------------------

pub fn now_epoch() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Lowercase hyphenated RFC-4122 text form of a vault UUID.
pub fn uuid_string(uuid: &VaultUuid) -> String {
    let b = uuid.0;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// UTC calendar date (`YYYY-MM-DD`) from unix seconds — civil-from-days
/// (Howard Hinnant's algorithm); std only.
pub fn iso_date(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Creates a directory (and parents) with 0700 (plan/02 §8). An existing
/// path is accepted only if it is a real directory (not a symlink someone
/// planted) with that mode; anything else is refused with the fix named.
pub fn create_secret_dir(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Err(_) => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(DIR_MODE_SECRET)
                .create(path)?;
            Ok(())
        }
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => Err(CliError::denied(
            format!(
                "{} exists but is not a plain directory (a symlink or a file)",
                path.display()
            ),
            Some(format!(
                "move it aside: mv {} {}.bak",
                path.display(),
                path.display()
            )),
        )),
        Ok(meta) if meta.permissions().mode() & 0o777 != DIR_MODE_SECRET => Err(CliError::denied(
            format!(
                "{} has mode {:o}, want {:o}",
                path.display(),
                meta.permissions().mode() & 0o777,
                DIR_MODE_SECRET
            ),
            Some(format!("chmod {:o} {}", DIR_MODE_SECRET, path.display())),
        )),
        Ok(_) => Ok(()),
    }
}

/// Writes a 0600 file, refusing to overwrite (identity material).
pub fn write_secret_file_exclusive(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE_SECRET)
        .open(path)
        .map_err(|e| {
            CliError::failure(
                format!("cannot create {}: {e}", path.display()),
                Some("choose a different label/path".to_owned()),
            )
        })?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_resolution_chain_is_flag_env_base() {
        assert_eq!(
            resolve_env_from(Some("prod"), Some("dev"))
                .unwrap()
                .as_str(),
            "prod"
        );
        assert_eq!(resolve_env_from(None, Some("dev")).unwrap().as_str(), "dev");
        assert_eq!(resolve_env_from(None, None).unwrap().as_str(), "base");
        assert!(resolve_env_from(Some("Bad Env"), None).is_err());
    }

    #[test]
    fn envvar_names_use_the_frozen_prefix() {
        use envholster_core::constants::ENV_VAR_PREFIX;
        assert!(ENVVAR_ENV.starts_with(ENV_VAR_PREFIX));
        assert!(ENVVAR_IDENTITY.starts_with(ENV_VAR_PREFIX));
        assert!(ENVVAR_IDENTITY_FILE.starts_with(ENV_VAR_PREFIX));
    }

    #[test]
    fn identity_text_parses_x25519_and_rejects_garbage() {
        let id = age::x25519::Identity::generate();
        use secrecy::ExposeSecret;
        let text = format!(
            "# created-at: 0\n# public key: {}\n{}\n",
            id.to_public(),
            id.to_string().expose_secret()
        );
        let parsed = parse_identity_text(&text, "test").unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(matches!(parsed[0], Identity::X25519(_)));

        assert!(parse_identity_text("not-an-identity\n", "test").is_err());
        assert!(parse_identity_text("# only comments\n", "test").is_err());
        // Plugin identities must be allowlisted (RUSTSEC-2024-0433).
        assert!(parse_identity_text("AGE-PLUGIN-EVIL-1QQQQQQQQQQQQQQQQQ\n", "test").is_err());
    }

    #[test]
    fn recovery_blob_path_matches_the_frozen_sibling_rule() {
        assert_eq!(
            recovery_blob_path(Path::new("/a/secrets.holster")),
            Path::new("/a/secrets.holster.recovery.age")
        );
    }

    #[test]
    fn uuid_and_date_formatting() {
        let uuid = VaultUuid([
            0x3f, 0x2a, 0x9c, 0x10, 0x88, 0xe2, 0x4c, 0x5b, 0x9d, 0x41, 0x6b, 0x7f, 0x0a, 0x2c,
            0x9e, 0x55,
        ]);
        assert_eq!(uuid_string(&uuid), "3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55");
        assert_eq!(iso_date(0), "1970-01-01");
        assert_eq!(iso_date(1_767_225_600), "2026-01-01");
    }

    /// Takes the lock the tests then contend for. Other tests in this binary
    /// start child processes, and one started while `create` held the lock
    /// keeps it briefly, so the holder needs the same wait.
    fn hold(path: &Path) -> Vault {
        open_vault_waiting(path, Duration::from_secs(5)).unwrap()
    }

    /// A fresh vault whose lock is released, for the busy-wait tests.
    fn released_vault(tag: &str) -> PathBuf {
        use envholster_core::{Enrollment, EnvSelector, RecipientClass, RecipientEntry, Tier};

        let dir = std::env::temp_dir().join(format!(
            "envholster-context-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(VAULT_FILENAME);
        let recovery = RecipientEntry::from_encoded(
            &age::x25519::Identity::generate().to_public().to_string(),
            RecipientClass::Recovery,
            "test-recovery".to_owned(),
            Enrollment(EnvSelector::All {
                max_tier: Tier::Critical,
            }),
        )
        .unwrap();
        let ctx = WrapContext::new(Arc::new(CliUi));
        drop(Vault::create(&path, vec![recovery], &ctx).unwrap());
        path
    }

    /// Two commands started together must not fail just because the other
    /// holds the lock for a moment.
    #[test]
    fn open_waits_out_a_brief_lock_holder() {
        let path = released_vault("brief");
        let holder = hold(&path);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(holder);
        });

        let opened = open_vault_waiting(&path, Duration::from_secs(5));
        release.join().unwrap();
        assert!(opened.is_ok(), "open failed: {:?}", opened.err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// A holder that outlasts the wait is a real conflict: the caller gets
    /// core's busy error, which the CLI maps to VAULT_BUSY.
    #[test]
    fn open_reports_busy_when_the_holder_outlasts_the_wait() {
        let path = released_vault("held");
        let holder = hold(&path);

        let started = Instant::now();
        let err = match open_vault_waiting(&path, Duration::from_millis(150)) {
            Ok(_) => panic!("opened a vault another holder still has"),
            Err(err) => err,
        };
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(
            matches!(&err, CoreError::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock),
            "unexpected error: {err:?}"
        );
        assert_eq!(CliError::from(err).code, "VAULT_BUSY");

        drop(holder);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
