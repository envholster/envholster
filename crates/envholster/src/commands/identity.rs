//! `identity {generate,list,import}` — X25519 identities at the fixed path
//! (0600 file, 0700 dir), documented discovery order (plan/07 §7.6–7.7).
//!
//! The secret half only ever lands in the 0600 identity file; commands print
//! public keys only. For CI, generate an identity on the runner the same way
//! and enroll its public key with `recipient add`.

use std::path::{Path, PathBuf};

use envholster_core::Identity;
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use crate::context::{
    create_secret_dir, identities_dir, identity_dir_files, iso_date, now_epoch,
    parse_identity_text, write_secret_file_exclusive,
};
use crate::errors::CliError;

fn validate_label(label: &str) -> Result<(), CliError> {
    let ok = !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(CliError::parse(
            format!("invalid identity label {label:?}: use [A-Za-z0-9._-]{{1,64}}"),
            None,
        ))
    }
}

fn identity_file_contents(identity: &age::x25519::Identity) -> String {
    format!(
        "# created: {}\n# public key: {}\n{}\n",
        iso_date(now_epoch()),
        identity.to_public(),
        identity.to_string().expose_secret()
    )
}

/// Returns (path, public key, label) of a usable local X25519 identity,
/// generating one at the fixed path when none exists. Used by `init`.
pub fn ensure_local_identity() -> Result<(PathBuf, String, String), CliError> {
    // `local.txt` FIRST, by name. The directory can hold several identities
    // (hardware stubs, a CI identity, an old machine's key), and "the first
    // file that parses" made init's choice depend on directory order — on a
    // real machine it picked `hwtest-machine.txt` over `local.txt`, and the
    // developer then had no way to know which one to unlock with. The default
    // identity has a fixed name; prefer it, then fall back to the scan.
    let preferred = identities_dir().join("local.txt");
    let mut candidates: Vec<PathBuf> = Vec::new();
    if preferred.is_file() {
        candidates.push(preferred.clone());
    }
    candidates.extend(identity_dir_files().into_iter().filter(|p| *p != preferred));
    for path in candidates {
        if let Ok(mut text) = std::fs::read_to_string(&path) {
            let found = text
                .lines()
                .map(str::trim)
                .find(|l| l.to_ascii_uppercase().starts_with("AGE-SECRET-KEY-1"))
                .and_then(|l| l.parse::<age::x25519::Identity>().ok());
            text.zeroize();
            if let Some(identity) = found {
                let label = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "local".to_owned());
                return Ok((path, identity.to_public().to_string(), label));
            }
        }
    }
    let label = "local".to_owned();
    let (path, public) = generate_to_file(&label)?;
    eprintln!(
        "Generated machine identity {} at {}",
        public,
        path.display()
    );
    Ok((path, public, label))
}

fn generate_to_file(label: &str) -> Result<(PathBuf, String), CliError> {
    validate_label(label)?;
    let dir = identities_dir();
    create_secret_dir(&dir)?;
    let path = dir.join(format!("{label}.txt"));
    if path.exists() {
        return Err(CliError::failure(
            format!("identity {} already exists", path.display()),
            Some(
                "choose a different --label, or use it as-is (envholster identity list)".to_owned(),
            ),
        ));
    }
    let identity = age::x25519::Identity::generate();
    let mut contents = identity_file_contents(&identity);
    write_secret_file_exclusive(&path, contents.as_bytes())?;
    contents.zeroize();
    Ok((path, identity.to_public().to_string()))
}

pub fn generate(label: &str) -> Result<(), CliError> {
    let (path, public) = generate_to_file(label)?;
    println!("public key: {public}");
    println!("identity file: {} (0600)", path.display());
    println!(
        "next: enroll it on a machine that can open the vault: \
         envholster recipient add {public} --class software --label {label}"
    );
    Ok(())
}

pub fn list() -> Result<(), CliError> {
    let files = identity_dir_files();
    if files.is_empty() {
        println!("no identities in {}", identities_dir().display());
        println!("next: envholster identity generate --label <label>");
        return Ok(());
    }
    for path in files {
        let label = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::read_to_string(&path) {
            Ok(mut text) => {
                match parse_identity_text(&text, &path.display().to_string()) {
                    Ok(identities) => {
                        for identity in identities {
                            let desc = match &identity {
                                Identity::X25519(id) => {
                                    format!("x25519 {}", id.to_public())
                                }
                                Identity::Plugin { name, .. } => {
                                    format!("plugin:{}", name.as_str())
                                }
                                Identity::Scrypt(_) => "scrypt".to_owned(),
                            };
                            println!("{label}\t{desc}\t{}", path.display());
                        }
                    }
                    Err(_) => println!("{label}\t(unparseable)\t{}", path.display()),
                }
                text.zeroize();
            }
            Err(e) => println!("{label}\t(unreadable: {e})\t{}", path.display()),
        }
    }
    Ok(())
}

pub fn import(source: &Path) -> Result<(), CliError> {
    let mut text = std::fs::read_to_string(source).map_err(|e| {
        CliError::not_found(
            format!("{} unreadable: {e}", source.display()),
            Some("pass a readable identity file to 'identity import'".to_owned()),
        )
    })?;
    // Must parse before it is adopted.
    parse_identity_text(&text, &source.display().to_string())?;

    let label = source
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "imported".to_owned());
    let label: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    validate_label(&label)?;

    let dir = identities_dir();
    create_secret_dir(&dir)?;
    let dest = dir.join(format!("{label}.txt"));
    write_secret_file_exclusive(&dest, text.as_bytes())?;
    text.zeroize();
    println!("imported {} -> {} (0600)", source.display(), dest.display());
    println!(
        "note: the source file still exists at {}; remove it if it should not remain there",
        source.display()
    );
    Ok(())
}
