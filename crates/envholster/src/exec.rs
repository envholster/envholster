//! In-process `run`: spawn a child with the vault's values in its environment.
//!
//! Lifted from the earlier daemon-era `envholster-broker-exec` crate
//! with the daemon-era pieces removed: no tier hard-deny
//! (the CLI decrypts what the identity can open, and that is the whole
//! policy), no `--mount` FIFO, no stdio descriptor passing (the child simply
//! inherits this process's terminal).
//!
//! What is kept, and why:
//!   * Spawn via nix's SAFE `posix_spawnp`; env entries are `ZeroizedCString`
//!     so the parent-side copies of every secret are zeroized the moment the
//!     vector drops. `std::process::Command` is deliberately NOT used for a
//!     secret-bearing environment: its internal copies are unreachable and never
//!     zeroized.
//!   * Secrets ride the child *environment*, never argv. argv is built from
//!     plain `CString`s; a secret value never touches `RunRequest::args`.
//!   * The child inherits this process's environment, minus a short deny list
//!     ([`filter_parent_env`]): the dynamic-loader hooks (`DYLD_*`, `LD_*`) that
//!     could inject code into a process about to hold secrets, the identity
//!     variables that would hand the child our key, and any name the manifest
//!     declares as a secret (a stale shell value must not shadow the vault).
//!   * Claim scope, stated plainly: parent-side residue is zeroized; the child's
//!     environ copy is inherently exposed for its lifetime (`KERN_PROCARGS2` /
//!     `/proc/<pid>/environ`) to any process running as the same user. PLAN.md
//!     says so, and `--dotenv` widens that to a 0600 file.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};

use envholster_mem::{process::ProcessSignals, SecretBytes};
use nix::spawn::{posix_spawnp, PosixSpawnAttr, PosixSpawnFileActions, PosixSpawnFlags};
use zeroize::{Zeroize, Zeroizing};

/// A secret value to inject into the child's environment for its lifetime.
/// Held in locked memory ([`SecretBytes`]) until the `ZeroizedCString` env
/// vector is built at spawn time.
pub struct InjectedEnv {
    /// Environment variable name (e.g. `DATABASE_URL`). Must be non-empty and
    /// contain neither `=` nor NUL (validated at build time).
    pub name: String,
    /// The secret value, exposed only inside a `with_exposed` closure while the
    /// env `CString` is built, then zeroized parent-side after spawn.
    pub value: SecretBytes,
}

/// A NUL-terminated environment entry whose bytes are zeroized on drop.
/// `CString` only zeroizes behind zeroize's `std` feature, which the pinned
/// dependency set does not enable; this wrapper needs nothing beyond
/// `Zeroizing<Vec<u8>>`. Callers reserve the trailing NUL up front so the
/// push here never reallocates and leaves an unzeroized copy behind.
pub struct ZeroizedCString(Zeroizing<Vec<u8>>);

impl ZeroizedCString {
    fn new(mut bytes: Vec<u8>) -> Result<Self, ()> {
        if bytes.contains(&0) {
            return Err(());
        }
        bytes.push(0);
        Ok(ZeroizedCString(Zeroizing::new(bytes)))
    }
}

impl AsRef<CStr> for ZeroizedCString {
    fn as_ref(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.0).expect("constructed with exactly one trailing NUL")
    }
}

/// A fully-specified spawn request.
pub struct RunRequest {
    /// argv[0] — resolved against the child PATH by `posix_spawnp`. A bare
    /// name is looked up on `base_env`'s `PATH`, which is this shell's PATH
    /// after filtering, so `npm` means the developer's `npm`.
    pub program: String,
    /// Remaining argv. A secret value MUST NEVER appear here.
    pub args: Vec<String>,
    /// The non-secret environment: this process's environment through
    /// [`filter_parent_env`], plus the manifest's `[vars]`.
    pub base_env: Vec<(String, String)>,
    /// Secret values to inject via the environment.
    pub injected: Vec<InjectedEnv>,
}

impl Drop for RunRequest {
    fn drop(&mut self) {
        // Composite settings may contain secrets despite originating in vars.
        for (_, value) in &mut self.base_env {
            value.zeroize();
        }
    }
}

/// Outcome of a spawn: the child pid to wait on.
pub struct RunHandle {
    pub child_pid: i32,
    /// Base-env names that were DROPPED because an injected secret claimed the
    /// same name — the injected secret always wins. Names only.
    pub shadowed_by_injection: Vec<String>,
}

/// Names that must never reach the child, whatever their source: the
/// dynamic-loader hooks and the identity variables. `run` checks the FINAL
/// environment against this, so a repository's `envholster.toml` cannot
/// smuggle an `LD_PRELOAD` in through `[vars]` any more than the shell can.
pub fn is_forbidden_delivery_name(name: &str) -> bool {
    name.starts_with("DYLD_")
        || name.starts_with("LD_")
        || name == "ENVHOLSTER_IDENTITY"
        || name == "ENVHOLSTER_IDENTITY_FILE"
}

/// The parent-environment policy for `run`. Everything passes through except:
///
///   * `DYLD_*` / `LD_*` — dynamic-loader hooks. Inheriting one would let a
///     library injected into the child read the secrets we just handed it,
///     and nothing a developer runs under `run` legitimately needs them.
///   * `ENVHOLSTER_IDENTITY` / `ENVHOLSTER_IDENTITY_FILE` — the child gets the
///     values, never the key that decrypts the vault.
///   * any name the manifest declares as a secret — a stale value exported in
///     the shell must not shadow the vault's. (`render_env` also drops any
///     remaining collision with an injected name, so this is belt and braces.)
pub fn filter_parent_env(
    parent: Vec<(String, String)>,
    declared_secret_names: &BTreeSet<String>,
) -> Vec<(String, String)> {
    parent
        .into_iter()
        .filter(|(name, _)| {
            !(is_forbidden_delivery_name(name) || declared_secret_names.contains(name))
        })
        .collect()
}

/// Validate an environment variable name: non-empty, no `=`, no NUL. `=` would
/// corrupt `KEY=VALUE` framing; NUL would truncate the C string.
fn validate_env_name(name: &str) -> Result<(), ExecError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&b'=') || bytes.contains(&0) {
        return Err(ExecError::InvalidEnvName(name.to_owned()));
    }
    Ok(())
}

/// Build a non-secret `KEY=VALUE` env entry. Wrapped in `Zeroizing` so the whole
/// env vector is one homogeneous, zeroize-on-drop type (harmless for non-secret
/// values; required for the injected ones).
fn build_plain_entry(name: &str, value: &str) -> Result<ZeroizedCString, ExecError> {
    validate_env_name(name)?;
    let mut buf = Vec::with_capacity(name.len() + 1 + value.len() + 1);
    buf.extend_from_slice(name.as_bytes());
    buf.push(b'=');
    buf.extend_from_slice(value.as_bytes());
    ZeroizedCString::new(buf).map_err(|_| ExecError::InteriorNul(name.to_owned()))
}

/// Build a secret `NAME=<secret>` env entry inside the value's `with_exposed`
/// closure. Capacity is reserved exactly (`name + '=' + secret + NUL`) so
/// `CString::new`'s trailing-NUL push never reallocates — the only heap copy of
/// the secret is the one owned by the returned `ZeroizedCString`, zeroized on
/// drop. The parent thus retains no unzeroized plaintext copy.
fn build_secret_entry(inj: &InjectedEnv) -> Result<ZeroizedCString, ExecError> {
    validate_env_name(&inj.name)?;
    let name = inj.name.as_str();
    inj.value.with_exposed(|sec| {
        if sec.contains(&0) {
            return Err(ExecError::InteriorNul(name.to_owned()));
        }
        let cap = name.len() + 1 + sec.len() + 1;
        let mut buf: Vec<u8> = Vec::with_capacity(cap);
        buf.extend_from_slice(name.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(sec);
        // Reserved capacity guarantees the trailing-NUL push does not
        // reallocate, so no stray plaintext buffer is left behind.
        ZeroizedCString::new(buf).map_err(|_| ExecError::InteriorNul(name.to_owned()))
    })
}

/// Assemble the child's complete environment as `ZeroizedCString` entries:
/// the filtered base env first, injected secrets second. Dropping the returned
/// vector zeroizes every secret-bearing entry.
///
/// COLLISION RULE: **the injected secret always wins.** Any base entry whose
/// name collides with an injected secret's name is DROPPED here, so the
/// child's environ carries exactly one entry for that name — the vault's.
/// Relying on libc's first-match `getenv` would be a latent bug: the base
/// entry comes first in this vector, so it would WIN without this filter.
fn render_env(
    base_env: &[(String, String)],
    injected: &[InjectedEnv],
) -> Result<(Vec<ZeroizedCString>, Vec<String>), ExecError> {
    let injected_names: BTreeSet<&str> = injected.iter().map(|i| i.name.as_str()).collect();
    let mut envp: Vec<ZeroizedCString> = Vec::with_capacity(base_env.len() + injected.len());
    let mut shadowed: Vec<String> = Vec::new();
    for (k, v) in base_env {
        if injected_names.contains(k.as_str()) {
            shadowed.push(k.clone());
            continue;
        }
        envp.push(build_plain_entry(k, v)?);
    }
    for inj in injected {
        envp.push(build_secret_entry(inj)?);
    }
    Ok((envp, shadowed))
}

/// Spawn `request` via `nix::spawn::posix_spawnp`, building the full env as
/// `ZeroizedCString` entries so no parent-side plaintext copy leaks. The
/// child inherits this process's stdin, stdout, stderr and working directory.
/// Returns the child pid.
pub fn run(request: RunRequest) -> Result<RunHandle, ExecError> {
    // Program + argv as plain CStrings. Secrets NEVER appear here.
    let program = CString::new(request.program.as_bytes())
        .map_err(|_| ExecError::InteriorNul("<program>".to_owned()))?;
    let mut argv: Vec<CString> = Vec::with_capacity(1 + request.args.len());
    argv.push(program.clone());
    for a in &request.args {
        argv.push(
            CString::new(a.as_bytes()).map_err(|_| ExecError::InteriorNul("<arg>".to_owned()))?,
        );
    }

    // Complete, authoritative child environment (base + injected).
    let (envp, shadowed_by_injection) = render_env(&request.base_env, &request.injected)?;

    let file_actions =
        PosixSpawnFileActions::init().map_err(|e| ExecError::SpawnSetup(e.to_string()))?;
    let mut attr = PosixSpawnAttr::init().map_err(|e| ExecError::SpawnSetup(e.to_string()))?;
    attr.set_pgroup(nix::unistd::Pid::from_raw(0))
        .map_err(|e| ExecError::SpawnSetup(e.to_string()))?;
    attr.set_flags(PosixSpawnFlags::POSIX_SPAWN_SETPGROUP)
        .map_err(|e| ExecError::SpawnSetup(e.to_string()))?;

    let pid = posix_spawnp(program.as_c_str(), &file_actions, &attr, &argv, &envp)
        .map_err(|e| ExecError::Spawn(e.to_string()))?;

    // `envp` (Vec<ZeroizedCString>) drops here → every injected secret's
    // parent-side heap copy is zeroized.
    Ok(RunHandle {
        child_pid: pid.as_raw(),
        shadowed_by_injection,
    })
}

/// Wait for the child to terminate and return the exit code the caller should
/// propagate: the exit status for a normal exit, or `128 + signal` for a
/// signalled death (the shell convention). Retries on `EINTR`.
pub fn wait(child_pid: i32, mut signals: Option<&mut ProcessSignals>) -> Result<i32, ExecError> {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;

    let pid = Pid::from_raw(child_pid);
    loop {
        if let Some(guard) = signals.as_deref_mut() {
            for signal in guard.take_pending() {
                ProcessSignals::signal_child(child_pid, signal).map_err(ExecError::Io)?;
            }
        }
        let flags = signals
            .as_ref()
            .map(|_| WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED);
        match waitpid(pid, flags) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Ok(WaitStatus::Stopped(_, _)) => {
                if let Some(guard) = signals.as_deref_mut() {
                    guard.child_stopped(child_pid).map_err(ExecError::Io)?;
                }
            }
            Ok(_) => {
                if let Some(guard) = signals.as_deref_mut() {
                    guard.wait_for_activity().map_err(ExecError::Io)?;
                }
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(ExecError::Wait(e.to_string())),
        }
    }
}

#[derive(Debug)]
pub enum ExecError {
    Io(std::io::Error),
    InvalidEnvName(String),
    InteriorNul(String),
    SpawnSetup(String),
    Spawn(String),
    Wait(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Io(e) => write!(f, "io error: {e}"),
            ExecError::InvalidEnvName(n) => write!(f, "invalid environment variable name: {n:?}"),
            ExecError::InteriorNul(n) => {
                write!(f, "environment entry {n:?} contains an interior NUL")
            }
            ExecError::SpawnSetup(e) => write!(f, "posix_spawn file-action/attr setup failed: {e}"),
            ExecError::Spawn(e) => write!(f, "could not start the command: {e}"),
            ExecError::Wait(e) => write!(f, "waitpid on the child failed: {e}"),
        }
    }
}

impl std::error::Error for ExecError {}

impl From<std::io::Error> for ExecError {
    fn from(e: std::io::Error) -> Self {
        ExecError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::waitpid;
    use nix::unistd::{pipe, Pid};
    use std::io::Read;
    use std::os::unix::io::AsRawFd;

    fn injected(name: &str, value: &str) -> InjectedEnv {
        InjectedEnv {
            name: name.to_owned(),
            value: SecretBytes::try_from_slice(value.as_bytes()).unwrap(),
        }
    }

    fn set(pairs: &[(&str, &str)]) -> BTreeSet<String> {
        pairs.iter().map(|(k, _)| (*k).to_owned()).collect()
    }

    fn cstrs(v: &[ZeroizedCString]) -> Vec<String> {
        v.iter()
            .map(|c| c.as_ref().to_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn render_env_is_base_then_injected_verbatim() {
        let base = vec![
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            ("HOME".to_owned(), "/home/u".to_owned()),
        ];
        let inj = vec![injected("API_KEY", "sk-live-1")];
        let (envp, shadowed) = render_env(&base, &inj).unwrap();
        assert_eq!(
            cstrs(&envp),
            vec!["PATH=/usr/bin", "HOME=/home/u", "API_KEY=sk-live-1"]
        );
        assert!(shadowed.is_empty());
    }

    #[test]
    fn injected_secret_wins_over_same_named_base_entry() {
        let base = vec![
            ("API_KEY".to_owned(), "stale-shell-value".to_owned()),
            ("PATH".to_owned(), "/usr/bin".to_owned()),
        ];
        let inj = vec![injected("API_KEY", "vault-value")];
        let (envp, shadowed) = render_env(&base, &inj).unwrap();
        assert_eq!(cstrs(&envp), vec!["PATH=/usr/bin", "API_KEY=vault-value"]);
        assert_eq!(shadowed, vec!["API_KEY".to_owned()]);
    }

    #[test]
    fn invalid_env_name_is_rejected() {
        assert!(matches!(
            build_plain_entry("BAD=NAME", "v"),
            Err(ExecError::InvalidEnvName(_))
        ));
        assert!(matches!(
            build_plain_entry("", "v"),
            Err(ExecError::InvalidEnvName(_))
        ));
        assert!(matches!(
            render_env(&[], &[injected("HAS\0NUL", "v")]),
            Err(ExecError::InvalidEnvName(_))
        ));
    }

    /// The deny list is exactly the loader hooks, the identity variables, and
    /// the declared secret names; everything else passes through unchanged.
    #[test]
    fn filter_parent_env_strips_dyld_ld_identity_and_declared_names() {
        let parent = vec![
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            ("TERM".to_owned(), "xterm".to_owned()),
            ("NODE_OPTIONS".to_owned(), "--x".to_owned()),
            ("DYLD_INSERT_LIBRARIES".to_owned(), "/e.dylib".to_owned()),
            ("LD_PRELOAD".to_owned(), "/e.so".to_owned()),
            (
                "ENVHOLSTER_IDENTITY".to_owned(),
                "AGE-SECRET-KEY-1X".to_owned(),
            ),
            ("ENVHOLSTER_IDENTITY_FILE".to_owned(), "/k".to_owned()),
            ("API_KEY".to_owned(), "stale".to_owned()),
            ("ENVHOLSTER_ENV".to_owned(), "prod".to_owned()),
        ];
        let declared = set(&[("API_KEY", "")]);
        let kept: Vec<String> = filter_parent_env(parent, &declared)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(kept, vec!["PATH", "TERM", "NODE_OPTIONS", "ENVHOLSTER_ENV"]);
    }

    fn drain(r: std::os::fd::OwnedFd) -> String {
        let mut out = String::new();
        std::fs::File::from(r).read_to_string(&mut out).unwrap();
        out
    }

    /// Shell redirect target for an inherited pipe fd. `>&N` is limited to a
    /// single digit in dash (Debian and Ubuntu `/bin/sh`), and the parallel
    /// test harness routinely hands out higher fds, so open the fd by path.
    fn fd_path(fd: &impl AsRawFd) -> String {
        format!("/dev/fd/{}", fd.as_raw_fd())
    }

    /// `run -- env` emits EXACTLY the filtered base plus the injected values.
    #[test]
    fn child_env_is_exactly_base_plus_injected() {
        let (r, w) = pipe().unwrap();
        let base = vec![
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("HOME".to_owned(), "/tmp".to_owned()),
        ];
        let req = RunRequest {
            program: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), format!("/usr/bin/env >{}", fd_path(&w))],
            base_env: base.clone(),
            injected: vec![injected("MY_TOKEN", "tok-abc-xyz")],
        };
        let handle = run(req).expect("spawn env");
        drop(w);
        let out = drain(r);
        waitpid(Pid::from_raw(handle.child_pid), None).unwrap();
        let mut got: Vec<&str> = out
            .lines()
            .filter(|l| !l.starts_with("PWD=") && !l.starts_with("SHLVL=") && !l.starts_with("_="))
            .collect();
        got.sort_unstable();
        let mut want = vec!["HOME=/tmp", "MY_TOKEN=tok-abc-xyz", "PATH=/usr/bin:/bin"];
        want.sort_unstable();
        assert_eq!(
            got, want,
            "child env must be exactly base + injected:\n{out}"
        );
    }

    /// The secret rides the environment, never argv.
    #[test]
    fn secret_is_in_child_env_not_in_argv() {
        let (r, w) = pipe().unwrap();
        let req = RunRequest {
            program: "/bin/sh".to_owned(),
            args: vec![
                "-c".to_owned(),
                format!("printf '%s|%s' \"$0 $*\" \"$MY_TOKEN\" >{}", fd_path(&w)),
                "argv0".to_owned(),
                "arg1".to_owned(),
            ],
            base_env: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
            injected: vec![injected("MY_TOKEN", "tok-in-env-only")],
        };
        let handle = run(req).unwrap();
        drop(w);
        let out = drain(r);
        waitpid(Pid::from_raw(handle.child_pid), None).unwrap();
        assert_eq!(out, "argv0 arg1|tok-in-env-only");
    }

    #[test]
    fn exit_code_propagates() {
        let req = RunRequest {
            program: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "exit 7".to_owned()],
            base_env: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
            injected: vec![],
        };
        let handle = run(req).unwrap();
        assert_eq!(wait(handle.child_pid, None).unwrap(), 7);
    }

    #[test]
    fn signalled_child_yields_128_plus() {
        let req = RunRequest {
            program: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "kill -TERM $$".to_owned()],
            base_env: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
            injected: vec![],
        };
        let handle = run(req).unwrap();
        assert_eq!(wait(handle.child_pid, None).unwrap(), 128 + 15);
    }
}
