//! `recovery {create,verify}` (RECOVERY-SPEC §5–§6).
//!
//! `init` parks the freshly generated recovery identity at
//! `~/.config/envholster/recovery/<vault-uuid>.identity`. `create` is the
//! ceremony that moves it off this machine: store to paper or removable
//! media, prove the copy AS STORED with a sentinel round trip and a full
//! `recovery verify`, and only then delete the parked file. `verify` proves
//! an OFFLINE recovery identity against the live vault, so the identity must
//! be supplied explicitly — a path/paste at an interactive prompt, or
//! `--identity` / `ENVHOLSTER_IDENTITY` / `ENVHOLSTER_IDENTITY_FILE` in
//! headless contexts. The fixed identity directory is deliberately NOT
//! consulted: a recovery identity living there is itself a finding.

use std::path::{Path, PathBuf};

use envholster_core::{Identity, RecipientClass, Vault};
use envholster_mem::SecretBytes;
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use crate::commands::init::read_identity_file;
use crate::context::{
    config_dir, discover_project, iso_date, now_epoch, open_vault, parse_identity_text,
    prompt_line, uuid_string, write_secret_file_exclusive, Session, ENVVAR_IDENTITY,
    ENVVAR_IDENTITY_FILE,
};
use crate::errors::CliError;

const FINGERPRINT_ATTEMPTS: usize = 5;
const SENTINEL_ATTEMPTS: usize = 3;

/// The frozen §4 one-liner, printed verbatim in the kit.
const DISASTER_ONE_LINER: &str = "age -d -i recovery-identity.txt secrets.holster.recovery.age \
| jq -r '.envs.prod.\"3\".DATABASE_URL.value' | base64 -d";

/// Where `init` parks recovery identities until `recovery create` runs.
pub fn recovery_dir() -> PathBuf {
    config_dir().join("recovery")
}

/// The parked identity for one vault.
pub fn parked_identity_path(vault_uuid: &str) -> PathBuf {
    recovery_dir().join(format!("{vault_uuid}.identity"))
}

/// Every parked identity on this machine (any vault).
pub fn parked_identities() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(recovery_dir()) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "identity"))
        .collect();
    files.sort();
    files
}

/// Kit items 4–6 plus fingerprint and UUID (RECOVERY-SPEC §6) — the identity
/// itself appears ONLY in the ceremony output, never here.
pub fn print_kit(fingerprint: &str, uuid: &str) {
    println!("=== envholster recovery kit ===");
    println!("fingerprint: {fingerprint}");
    println!("vault uuid:  {uuid}");
    println!("printed:     {}", iso_date(now_epoch()));
    println!();
    println!("Disaster recovery needs only the paper/removable identity, the two committed");
    println!("files (secrets.holster, secrets.holster.recovery.age), and the `age` + `jq`");
    println!("CLIs — zero envholster code. The frozen one-liner (substitute env/tier/name):");
    println!();
    println!("    {DISASTER_ONE_LINER}");
    println!();
    println!("Print docs/RECOVERY-SPEC.md into the kit alongside this page; it carries the");
    println!("full procedure, the canonical JSON layout, and the honest limits.");
    println!();
    println!("The recovery identity was shown or written ONCE and is never re-printable.");
    println!("Verify the stored copy any time: envholster recovery verify");
}

/// Is `path` on this machine's own storage? The same filesystem as HOME,
/// the config dir, the project, or the root volume, or anywhere under a
/// temp directory. Removable media mounts as its own filesystem, which is what
/// the device-number comparison detects; a mount the heuristic cannot tell
/// apart needs `--allow-same-disk`.
pub(crate) fn on_this_machines_disk(path: &Path, project_root: &Path) -> Result<bool, CliError> {
    use std::os::unix::fs::MetadataExt;
    // A bare file name means the current directory (the operator has cd'd
    // onto the media); a directory that does not exist is its own refusal,
    // with its own reason, since nothing is mounted there.
    let dest_dir = match path.parent() {
        Some(p) if p.as_os_str().is_empty() => PathBuf::from("."),
        Some(p) => p.to_path_buf(),
        None => PathBuf::from("."),
    };
    if !dest_dir.is_dir() {
        return Err(CliError::not_found(
            format!(
                "the destination directory {} does not exist (is the media mounted?)",
                dest_dir.display()
            ),
            Some("mount the removable media, then re-run recovery create --to <path>".to_owned()),
        ));
    }
    let dest_dir = dest_dir.canonicalize().unwrap_or(dest_dir);
    let temp = std::env::temp_dir();
    for prefix in [
        temp.as_path(),
        Path::new("/tmp"),
        Path::new("/private/tmp"),
        Path::new("/var/tmp"),
    ] {
        if dest_dir.starts_with(prefix) {
            return Ok(true);
        }
    }
    let dest_dev = std::fs::metadata(&dest_dir).map(|m| m.dev())?;
    // The machine's own storage: the root volume, HOME, the config dir, and
    // the disk the project (and so the vault this key must outlive) sits on.
    // NOT the current directory: an operator who has cd'd onto the mounted
    // media and typed a bare file name must not be told the media is local.
    let mut local: Vec<PathBuf> =
        vec![PathBuf::from("/"), config_dir(), project_root.to_path_buf()];
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            local.push(PathBuf::from(home));
        }
    }
    Ok(local
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .any(|m| m.dev() == dest_dev))
}

/// File-only onboarding recovery never displays key material, and resumes a
/// completed write by authenticating the existing copy before retiring the parked key.
pub(crate) fn guided_save(
    session: &Session,
    path: &Path,
    allow_same_disk: bool,
) -> Result<(), CliError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let project = discover_project()?;
    crate::setup::safe_path(path)?;
    if path.starts_with(&project.root) {
        return Err(CliError::denied(
            "Choose a recovery folder outside the project",
            Some("envholster setup".into()),
        ));
    }
    if on_this_machines_disk(path, &project.root)? && !allow_same_disk {
        return Err(CliError::denied("The recovery folder is on this computer. Choose removable storage, or explicitly confirm a local copy with --allow-same-disk.", Some("envholster setup".into())));
    }
    let vault = open_vault(&project)?;
    let public = vault
        .recipients()
        .iter()
        .find(|r| r.class == RecipientClass::Recovery)
        .and_then(|r| r.encoded.as_ref())
        .ok_or_else(|| CliError::failure("The vault has no recovery recipient", None))?;
    let parked = parked_identity_path(&uuid_string(&vault.uuid()));
    if path == parked {
        return Err(CliError::denied(
            "The parked key cannot be its own recovery destination",
            None,
        ));
    }
    if !path.try_exists()? {
        if !parked.try_exists()? {
            return Err(CliError::failure("This vault already has a saved recovery key. Select this project alone and rerun setup with --recovery-file PATH to verify that existing copy.", Some("envholster setup --help".into())));
        }
        let identity = read_identity_file(&parked)?;
        if identity.to_public().to_string() != *public {
            return Err(CliError::failure(
                "The parked recovery key does not match the vault",
                None,
            ));
        }
        let contents = zeroize::Zeroizing::new(format!(
            "# Envholster recovery identity. Keep offline.\n{}\n",
            identity.to_string().expose_secret()
        ));
        write_secret_file_exclusive(path, contents.as_bytes())?;
    }
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.permissions().mode() & 0o077 != 0 {
        return Err(CliError::denied(
            "The recovery copy must be an unshared private file with mode 0600",
            None,
        ));
    }
    let stored = read_identity_file(path)?;
    if stored.to_public().to_string() != *public {
        return Err(CliError::failure(
            "The existing recovery file belongs to a different vault and was not changed",
            Some("envholster setup".into()),
        ));
    }
    vault
        .recovery_test(&[Identity::X25519(stored)], &session.ui)
        .map_err(CliError::from)?;
    std::fs::File::open(path)?.sync_all()?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    if parked.is_file() {
        let original = read_identity_file(&parked)?;
        if original.to_public().to_string() != *public {
            return Err(CliError::failure(
                "The parked recovery key changed; it was kept",
                None,
            ));
        }
        std::fs::remove_file(parked)?;
    }
    println!("Recovery copy saved and verified: {}", path.display());
    Ok(())
}

/// `recovery create [--to <path> | --paper] [--allow-same-disk]`: move the
/// parked identity off this machine, prove the stored copy, delete the
/// parked file.
pub fn create(
    session: &mut Session,
    to: Option<&Path>,
    paper: bool,
    allow_same_disk: bool,
) -> Result<(), CliError> {
    let project = discover_project()?;
    let vault = open_vault(&project)?;
    let uuid = uuid_string(&vault.uuid());
    let recovery_entry = vault
        .recipients()
        .iter()
        .find(|r| r.class == RecipientClass::Recovery)
        .ok_or_else(|| {
            CliError::failure(
                "vault has no recovery recipient — the header is damaged; restore from git",
                None,
            )
        })?;
    let fingerprint = recovery_entry.id.as_str().to_owned();
    let recovery_public = recovery_entry.encoded.clone().unwrap_or_default();

    let parked = parked_identity_path(&uuid);
    if !parked.is_file() {
        return Err(CliError::failure(
            "kit already created; use `envholster recovery verify`",
            Some("envholster recovery verify".to_owned()),
        ));
    }
    let recovery_identity = read_identity_file(&parked)?;
    if recovery_identity.to_public().to_string() != recovery_public {
        return Err(CliError::failure(
            format!(
                "{} does not match this vault's recovery recipient ({fingerprint})",
                parked.display()
            ),
            Some("envholster recipient list".to_owned()),
        ));
    }

    eprintln!("=== Recovery ceremony ===");
    eprintln!("The recovery identity is a master key: it decrypts every environment,");
    eprintln!("every tier, and every past generation in git history. After this step it");
    eprintln!("exists ONLY on paper or removable media — never on this machine's disk.");
    eprintln!();

    let removable_path: Option<PathBuf> = match (to, paper) {
        (Some(path), _) => Some(path.to_owned()),
        (None, true) => None,
        (None, false) => loop {
            let choice = prompt_line(
                "Store the recovery identity on [1] paper or [2] removable media? [1/2]: ",
                "envholster recovery create --paper | --to <removable path>",
            )?;
            match choice.as_str() {
                "1" | "paper" | "" => break None,
                "2" | "removable" => {
                    let path = prompt_line(
                        "Removable media path for the identity file: ",
                        "envholster recovery create --to <removable path>",
                    )?;
                    if path.is_empty() {
                        continue;
                    }
                    break Some(PathBuf::from(path));
                }
                _ => continue,
            }
        },
    };

    match &removable_path {
        Some(path) => {
            if on_this_machines_disk(path, &project.root)? {
                if !allow_same_disk {
                    return Err(CliError::denied(
                        format!(
                            "{} is on this machine's own disk (the same filesystem as your home \
                             directory, the project, or a temp directory) — the recovery identity \
                             must leave the machine, and the parked copy would be deleted",
                            path.display()
                        ),
                        Some(
                            "mount removable media and pass its path with --to, use --paper, or \
                             pass --allow-same-disk only if you know this path really is separate \
                             storage"
                                .to_owned(),
                        ),
                    ));
                }
                eprintln!(
                    "WARNING: {} is on this machine's disk (--allow-same-disk given). If this \
                     machine is lost, so is the recovery identity.",
                    path.display()
                );
            }
            let mut contents = format!(
                "# envholster recovery identity — keep OFFLINE\n# created: {}\n# public key: {}\n{}\n",
                iso_date(now_epoch()),
                recovery_public,
                recovery_identity.to_string().expose_secret()
            );
            write_secret_file_exclusive(path, contents.as_bytes())?;
            contents.zeroize();
            eprintln!("Recovery identity written to {} (0600).", path.display());
        }
        None => {
            eprintln!("Write down or print the following identity now — it is shown ONCE and");
            eprintln!("is never re-printable. Render a QR code from this exact string if your");
            eprintln!("kit needs one.");
            eprintln!();
            eprintln!("    {}", recovery_identity.to_string().expose_secret());
            eprintln!();
            // Fingerprint re-entry proves the operator recorded what they saw;
            // a file written by us needs no such proof.
            eprintln!("Recovery fingerprint: {fingerprint}");
            let mut confirmed = false;
            for _ in 0..FINGERPRINT_ATTEMPTS {
                let entered = prompt_line(
                    "Re-enter the fingerprint exactly: ",
                    "envholster recovery create --paper needs a terminal",
                )?;
                if entered == fingerprint {
                    confirmed = true;
                    break;
                }
                eprintln!("Mismatch. The fingerprint is: {fingerprint}");
            }
            if !confirmed {
                return Err(CliError::failure(
                    "fingerprint re-entry failed — the parked identity stays on this machine; \
                     run the ceremony again",
                    Some("envholster recovery create".to_owned()),
                ));
            }
        }
    }

    // Sentinel round-trip proof with the identity AS STORED.
    let sentinel = SecretBytes::try_random(32)
        .map_err(|e| CliError::failure(format!("entropy failure: {e}"), None))?;
    let sentinel_bytes: Vec<u8> = sentinel.with_exposed(|b| b.to_vec());
    let ciphertext = age::encrypt(&recovery_identity.to_public(), &sentinel_bytes)
        .map_err(|e| CliError::failure(format!("sentinel encryption failed: {e}"), None))?;

    let mut proven: Option<age::x25519::Identity> = None;
    for attempt in 0..SENTINEL_ATTEMPTS {
        let stored: Option<age::x25519::Identity> = match &removable_path {
            Some(path) => match read_identity_file(path) {
                Ok(identity) => Some(identity),
                Err(e) => {
                    eprintln!("Could not read the identity back from removable media: {e}");
                    None
                }
            },
            None => match crate::context::prompt_secret_string(
                "Re-enter the FULL recovery identity from your paper copy (no echo): ",
            )? {
                Some(mut typed) => {
                    let parsed = typed.trim().parse::<age::x25519::Identity>().ok();
                    typed.zeroize();
                    if parsed.is_none() {
                        eprintln!("That is not a valid AGE-SECRET-KEY-1... string.");
                    }
                    parsed
                }
                None => {
                    return Err(CliError::interactive_required(
                        "the paper-copy re-entry (sentinel proof)",
                        "envholster recovery create --paper",
                    ))
                }
            },
        };
        if let Some(identity) = stored {
            match age::decrypt(&identity, &ciphertext) {
                Ok(plain) if plain == sentinel_bytes => {
                    proven = Some(identity);
                    break;
                }
                _ => eprintln!("Sentinel round-trip FAILED — the stored identity is wrong."),
            }
        }
        if attempt + 1 < SENTINEL_ATTEMPTS {
            eprintln!(
                "Try again ({} attempts left).",
                SENTINEL_ATTEMPTS - attempt - 1
            );
        }
    }
    let Some(stored_identity) = proven else {
        return Err(CliError::failure(
            "sentinel round-trip proof failed — the parked identity stays on this machine; an \
             untested recovery path is treated as no recovery path",
            Some("envholster recovery create".to_owned()),
        ));
    };
    eprintln!("Sentinel round-trip proof OK.");

    // The full recovery proof against the live vault, with ONLY the stored
    // identity, before the on-disk copy goes away.
    vault
        .recovery_test(&[Identity::X25519(stored_identity)], &session.ui)
        .map_err(|e| {
            CliError::from(e).with_next(
                "the parked identity was kept; re-save the vault (any write op) to restore \
                 lockstep and run 'envholster recovery create' again",
            )
        })?;
    std::fs::remove_file(&parked)?;
    eprintln!(
        "Recovery verified; the on-disk copy at {} was deleted.",
        parked.display()
    );
    println!();
    print_kit(&fingerprint, &uuid);
    Ok(())
}

/// Without an explicit source, require the operator's stored kit copy.
fn acquire_recovery_identity() -> Result<Vec<Identity>, CliError> {
    let answer = prompt_line(
        "Recovery identity — enter the file path on your removable media, or press Enter \
         to paste the key: ",
        "envholster recovery verify --identity <path-to-recovery-identity>",
    )?;
    if answer.is_empty() {
        let mut typed = crate::context::prompt_secret_string(
            "Paste the recovery identity (AGE-SECRET-KEY-1..., no echo): ",
        )?
        .ok_or_else(|| {
            CliError::interactive_required(
                "supplying the recovery identity",
                "envholster recovery verify --identity <path-to-recovery-identity>",
            )
        })?;
        let parsed = typed.trim().parse::<age::x25519::Identity>().ok();
        typed.zeroize();
        return parsed
            .map(|id| vec![Identity::X25519(id)])
            .ok_or_else(|| CliError::parse("not a valid AGE-SECRET-KEY-1... string", None));
    }
    let path = Path::new(&answer);
    let text =
        zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
            CliError::not_found(format!("{} unreadable: {e}", path.display()), None)
        })?);
    parse_identity_text(&text, &path.display().to_string())
}

pub fn verify(session: &mut Session) -> Result<(), CliError> {
    let project = discover_project()?;
    let vault = open_vault(&project)?;
    run_verify(session, &vault)?;
    println!("recovery verify OK: every cell's recovery wrap unwraps and the recovery blob");
    println!(
        "matches every authenticated vault record (generation {}, uuid {}).",
        vault.generation(),
        uuid_string(&vault.uuid())
    );
    Ok(())
}

fn run_verify(session: &Session, vault: &Vault) -> Result<(), CliError> {
    let inline = std::env::var(ENVVAR_IDENTITY)
        .map(zeroize::Zeroizing::new)
        .ok();
    let has_explicit = session.identity_flag.is_some()
        || inline
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty())
        || std::env::var(ENVVAR_IDENTITY_FILE).is_ok_and(|value| !value.is_empty());
    let prompted;
    let identities = if has_explicit {
        session.identities.as_slice()
    } else {
        prompted = acquire_recovery_identity()?;
        &prompted
    };
    vault.recovery_test(identities, &session.ui).map_err(|e| {
        CliError::from(e).with_next(
            "if the identity is correct, re-save the vault to restore lockstep (any write \
                 op) and retry 'envholster recovery verify'; if it is wrong, this vault's kit \
                 fingerprint is shown by 'envholster recipient list'",
        )
    })
}
