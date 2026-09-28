//! `init` — vault + manifest creation with no ceremony (PLAN.md;
//! RECOVERY-SPEC §1). The recovery identity is generated here and parked on
//! this machine at `~/.config/envholster/recovery/<vault-uuid>.identity`
//! (0600) until `envholster recovery create` moves it to paper or removable
//! media; `doctor` reports the parked file until it is gone.
//!
//! `init --recover-from` is machine-loss re-enrollment: prove the offline
//! recovery identity against the committed vault, then enroll a fresh machine
//! identity through the recovery unwraps.

use std::path::Path;

use envholster_core::constants::{MANIFEST_FILENAME, VAULT_FILENAME};
use envholster_core::{
    Enrollment, EnvSelector, Identity, RecipientClass, RecipientEntry, Tier, Vault,
};
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use crate::commands::identity::ensure_local_identity;
use crate::commands::merge_driver::ensure_merge_driver;
use crate::commands::recovery::{parked_identity_path, recovery_dir};
use crate::context::{
    create_secret_dir, discover_project, iso_date, now_epoch, uuid_string,
    write_secret_file_exclusive, Session,
};
use crate::errors::CliError;
use crate::manifestio::{empty_manifest, store_manifest};

/// Rules `init` appends to `.gitignore` when absent: the personal override
/// file and every plaintext dotenv, with the conventional example file kept.
const GITIGNORE_RULES: [&str; 5] = [
    "envholster.local.toml",
    "secrets.holster.lock",
    ".env",
    ".env.*",
    "!.env.example",
];

pub fn run(
    session: &mut Session,
    recipients: &[String],
    recover_from: Option<&str>,
) -> Result<(), CliError> {
    if let Some(source) = recover_from {
        return recover(session, source);
    }

    let cwd = std::env::current_dir()?;
    let vault_path = cwd.join(VAULT_FILENAME);
    let manifest_path = cwd.join(MANIFEST_FILENAME);
    if vault_path.exists() {
        return Err(CliError::failure(
            format!("vault {} already exists", vault_path.display()),
            Some("envholster status".to_owned()),
        ));
    }
    let (identity_path, machine_public, machine_label) = ensure_local_identity()?;
    eprintln!(
        "Machine identity: {} ({})",
        machine_public,
        identity_path.display()
    );

    let mut entries: Vec<RecipientEntry> = Vec::new();
    entries.push(
        RecipientEntry::from_encoded(
            &machine_public,
            RecipientClass::Software,
            machine_label,
            Enrollment(EnvSelector::All {
                max_tier: Tier::Ambient,
            }),
        )
        .map_err(CliError::from)?,
    );
    for (i, encoded) in recipients.iter().enumerate() {
        let entry = initial_recipient(encoded, i)?;
        if entries.iter().any(|e| e.id == entry.id) {
            eprintln!(
                "note: --recipient {} is already enrolled (it is this machine's identity); \
                 skipping the duplicate",
                entry.id.as_str()
            );
            continue;
        }
        entries.push(entry);
    }

    let recovery_identity = age::x25519::Identity::generate();
    let recovery_public = recovery_identity.to_public().to_string();
    let recovery_entry = RecipientEntry::from_encoded(
        &recovery_public,
        RecipientClass::Recovery,
        "recovery".to_owned(),
        Enrollment(EnvSelector::All {
            max_tier: Tier::Critical,
        }),
    )
    .map_err(CliError::from)?;
    let fingerprint = recovery_entry.id.as_str().to_owned();
    entries.push(recovery_entry);

    // Park the recovery identity BEFORE creating the vault: a crash between
    // the two leaves a key with nothing to open, never a vault with no key.
    // The vault uuid is only known after `create`, so write under a pending
    // name and rename.
    let dir = recovery_dir();
    create_secret_dir(&dir)?;
    let pending = dir.join(format!("pending-{}.identity", std::process::id()));
    let mut contents = format!(
        "# envholster recovery identity — move it offline: envholster recovery create\n\
         # created: {}\n# public key: {}\n{}\n",
        iso_date(now_epoch()),
        recovery_public,
        recovery_identity.to_string().expose_secret()
    );
    write_secret_file_exclusive(&pending, contents.as_bytes())?;
    contents.zeroize();

    let vault = match Vault::create(&vault_path, entries, &session.ui) {
        Ok(vault) => vault,
        Err(e) => {
            let _ = std::fs::remove_file(&pending);
            return Err(CliError::from(e));
        }
    };
    let uuid = uuid_string(&vault.uuid());
    let parked = parked_identity_path(&uuid);
    std::fs::rename(&pending, &parked)?;

    if !manifest_path.exists() {
        store_manifest(&manifest_path, &empty_manifest())?;
    }
    ensure_gitignore(&cwd)?;
    ensure_merge_driver(&cwd);

    println!("Initialized envholster project in {}", cwd.display());
    println!("  vault:    {}", vault_path.display());
    println!("  manifest: {}", manifest_path.display());
    println!("  recovery fingerprint: {fingerprint}");
    println!();
    println!(
        "Vault created. Your recovery key is on this machine at {}. Run `envholster recovery \
         create` to move it to paper or a USB stick; `doctor` will remind you.",
        parked.display()
    );
    Ok(())
}

/// Append the plaintext-dotenv rules to `.gitignore` when missing (creating
/// the file if needed). Existing content is never rewritten.
pub fn ensure_gitignore(root: &Path) -> Result<Vec<&'static str>, CliError> {
    let path = root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let missing: Vec<&'static str> = GITIGNORE_RULES
        .iter()
        .copied()
        .filter(|rule| !existing.lines().any(|l| l.trim() == *rule))
        .collect();
    if missing.is_empty() {
        return Ok(missing);
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str("# envholster: plaintext secrets never enter git\n");
    for rule in &missing {
        text.push_str(rule);
        text.push('\n');
    }
    std::fs::write(&path, text)?;
    Ok(missing)
}

/// `--recipient <age1...>`: class inferred from the encoding — plugin
/// recipients are hardware (enrolled *:3), X25519 are software (*:1, G-A).
/// Full control (named envs, per-env tiers): `envholster recipient add`.
fn initial_recipient(encoded: &str, index: usize) -> Result<RecipientEntry, CliError> {
    let label = format!("init-recipient-{}", index + 1);
    let hardware = RecipientEntry::from_encoded(
        encoded,
        RecipientClass::Hardware,
        label.clone(),
        Enrollment(EnvSelector::All {
            max_tier: Tier::Critical,
        }),
    );
    if let Ok(entry) = hardware {
        return Ok(entry);
    }
    RecipientEntry::from_encoded(
        encoded,
        RecipientClass::Software,
        label,
        Enrollment(EnvSelector::All {
            max_tier: Tier::Ambient,
        }),
    )
    .map_err(|e| {
        CliError::from(e).with_next(
            "pass a valid age recipient (age1... or age1yubikey1.../age1se1...) to --recipient",
        )
    })
}

pub fn read_identity_file(path: &Path) -> Result<age::x25519::Identity, CliError> {
    let mut text = std::fs::read_to_string(path)
        .map_err(|e| CliError::failure(format!("{} unreadable: {e}", path.display()), None))?;
    let parsed = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .and_then(|l| l.parse::<age::x25519::Identity>().ok());
    text.zeroize();
    parsed.ok_or_else(|| {
        CliError::parse(
            format!(
                "{} does not contain an AGE-SECRET-KEY-1... identity",
                path.display()
            ),
            None,
        )
    })
}

/// `init --recover-from <identity-file|->`: machine loss. The operator
/// supplies the offline recovery identity ('-' = paste at a no-echo prompt);
/// envholster proves it against the committed vault and re-enrolls a fresh
/// machine identity by re-wrapping via the recovery unwraps (RECOVERY-SPEC §5).
fn recover(session: &mut Session, source: &str) -> Result<(), CliError> {
    let project = discover_project()?;
    let mut vault = crate::context::open_vault(&project)?;

    let recovery_identity = if source == "-" {
        let mut typed = crate::context::prompt_secret_string(
            "Paste the recovery identity (AGE-SECRET-KEY-1..., no echo): ",
        )?
        .ok_or_else(|| {
            CliError::interactive_required(
                "pasting the recovery identity",
                "pass a file path to --recover-from instead",
            )
        })?;
        let parsed = typed.trim().parse::<age::x25519::Identity>().ok();
        typed.zeroize();
        parsed.ok_or_else(|| CliError::parse("not a valid AGE-SECRET-KEY-1... string", None))?
    } else {
        read_identity_file(Path::new(source))?
    };

    // Prove the identity against the live vault BEFORE touching anything.
    let identities = [Identity::X25519(recovery_identity)];
    vault.recovery_test(&identities, &session.ui).map_err(|e| {
        CliError::from(e).with_next(
            "supply the correct recovery identity for THIS vault (check the kit fingerprint \
             against 'envholster recipient list')",
        )
    })?;

    let (identity_path, machine_public, machine_label) = ensure_local_identity()?;
    let entry = RecipientEntry::from_encoded(
        &machine_public,
        RecipientClass::Software,
        machine_label,
        Enrollment(EnvSelector::All {
            max_tier: Tier::Ambient,
        }),
    )
    .map_err(CliError::from)?;

    vault
        .add_recipient(entry, &identities, &session.ui)
        .map_err(CliError::from)?;
    vault.save().map_err(CliError::from)?;
    vault
        .recovery_test(&identities, &session.ui)
        .map_err(CliError::from)?;

    println!(
        "Re-enrolled this machine ({}) as a software recipient (tier-1 cells).",
        machine_public
    );
    println!("  identity file: {}", identity_path.display());
    println!(
        "Tier >= 2 cells stay hardware-only; re-enroll hardware with \
         'envholster recipient add ... --class hardware'."
    );
    if source != "-" {
        println!(
            "Reminder: the recovery identity must return to offline storage; if {} is on this \
             machine's disk, remove it ('envholster doctor' scans for it).",
            source
        );
    }
    Ok(())
}
