//! `merge-driver <base> <ours> <theirs>` — a git merge driver for
//! `secrets.holster`, plus the `.gitattributes` / `git config` wiring `init`
//! and `import` install so git actually calls it.
//!
//! Two people adding different secrets on two branches must not end in a
//! binary conflict. The driver opens all three vaults, checks they descend
//! from the same created vault (same UUID — unrelated vaults are not
//! branches of one history), unlocks what the local identities can, and
//! merges record by record: a record changed on one side only takes that
//! side whole (value, mode, rotation state, metadata); the same change on
//! both sides is fine; different changes to the same record are a conflict
//! git reports the ordinary way. Recipient sets are trust decisions, not
//! mergeable data: any difference is a conflict resolved by choosing a side
//! and running `envholster recipient add` deliberately. A tier >= 2 cell
//! this machine cannot unlock cannot be merged here (its bytes are opaque),
//! which is reported, not guessed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use envholster_core::constants::{RECOVERY_FILENAME, VAULT_FILENAME};
use envholster_core::{CellId, Guarantee, SecretMode, SecretRecord, Vault};
use envholster_mem::SecretBytes;
use zeroize::Zeroizing;

use crate::context::{create_secret_dir, uuid_string, write_secret_file_exclusive, Session};
use crate::errors::{CliError, EXIT_FAILURE, EXIT_OK};

const ATTRIBUTES: [&str; 2] = [
    "secrets.holster merge=envholster",
    "secrets.holster.recovery.age merge=envholster-blob",
];
const GIT_CONFIG: [(&str, &str); 4] = [
    ("merge.envholster.name", "envholster vault merge"),
    (
        "merge.envholster.driver",
        "envholster merge-driver %O %A %B",
    ),
    // The recovery blob is never merged byte-wise: its driver takes the blob
    // the vault driver regenerated from the merged vault (see
    // `merge_side_dir`), so the merge commit carries a blob in lockstep.
    ("merge.envholster-blob.name", "envholster recovery blob"),
    (
        "merge.envholster-blob.driver",
        "envholster merge-driver-blob %O %A %B",
    ),
];

/// The hand-off between the two drivers. git runs one driver per path and
/// commits each driver's `%A`; the blob's correct content only exists once
/// the vault driver has saved the merged vault. The vault driver parks the
/// regenerated blob under `<git-dir>/envholster-merge/`, and the blob driver
/// (git processes `secrets.holster` before `secrets.holster.recovery.age`,
/// index order) returns it through its own `%A`. `None` outside a git
/// repository (the driver invoked by hand).
fn merge_side_dir() -> Option<PathBuf> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let git_dir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    Some(git_dir.join("envholster-merge"))
}

fn clear_side_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// `merge-driver-blob <base> <ours> <theirs>`: hand git the blob the vault
/// driver regenerated. Without one (the vault driver has not run, or it
/// hit a conflict) the merge must stop here rather than commit a stale blob
/// that would fail `recovery verify` from a fresh clone.
pub fn run_blob(ours: &Path) -> Result<i32, CliError> {
    let parked: Vec<PathBuf> = merge_side_dir()
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect()
        })
        .unwrap_or_default();
    // A parked blob belongs to the merge in progress: the vault driver clears
    // the directory on every run, so a lone stale file can only be one an
    // abandoned merge left behind minutes or days ago. Age is the cheap tell.
    let fresh = |p: &PathBuf| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < std::time::Duration::from_secs(15 * 60))
    };
    if let [src] = parked.as_slice() {
        if !fresh(src) {
            let _ = std::fs::remove_file(src);
            eprintln!("merge-driver: ignored a stale parked recovery blob from an earlier merge");
            return Ok(EXIT_FAILURE);
        }
        std::fs::copy(src, ours)?;
        let _ = std::fs::remove_file(src);
        eprintln!("merge-driver: recovery blob regenerated from the merged vault");
        return Ok(EXIT_OK);
    }
    eprintln!(
        "CONFLICT (envholster): secrets.holster.recovery.age must be regenerated from the merged \
         vault, not merged. Resolve secrets.holster first, run any envholster write (for example \
         'envholster set' on an existing secret) so the blob is regenerated, then: git add \
         secrets.holster secrets.holster.recovery.age && git commit"
    );
    Ok(EXIT_FAILURE)
}

/// Append the merge attributes to `<root>/.gitattributes` when absent and,
/// inside a git repository, set the driver config. Best effort: a project
/// that is not a git repo simply gets the attributes file for later.
pub fn ensure_merge_driver(root: &Path) {
    let path = root.join(".gitattributes");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut add = String::new();
    for line in ATTRIBUTES {
        if !existing.lines().any(|l| l.trim() == line) {
            add.push_str(line);
            add.push('\n');
        }
    }
    if !add.is_empty() {
        let mut text = existing;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&add);
        let _ = std::fs::write(&path, text);
    }
    if in_git_repo(root) {
        for (key, value) in GIT_CONFIG {
            let _ = std::process::Command::new("git")
                .args(["config", key, value])
                .current_dir(root)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

/// What `doctor` reports: every attribute line or config key that is
/// missing. Empty means the driver is wired up (or the project is not a git
/// repository, where only the attributes file can exist).
pub fn missing_merge_driver_config(root: &Path) -> Vec<String> {
    let mut missing = Vec::new();
    let attrs = std::fs::read_to_string(root.join(".gitattributes")).unwrap_or_default();
    for line in ATTRIBUTES {
        if !attrs.lines().any(|l| l.trim() == line) {
            missing.push(format!(".gitattributes line `{line}`"));
        }
    }
    if in_git_repo(root) {
        for (key, value) in GIT_CONFIG {
            let got = std::process::Command::new("git")
                .args(["config", "--get", key])
                .current_dir(root)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
            if got.as_deref() != Some(value) {
                missing.push(format!("git config {key} \"{value}\""));
            }
        }
    }
    missing
}

fn in_git_repo(root: &Path) -> bool {
    std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Scratch directory (0700) holding the three vault copies; removed on drop.
struct Scratch(PathBuf);

/// A scratch directory nobody could have pre-created: a random name under the
/// temp dir, created with `create_new` semantics (mode 0700, no following of
/// a planted symlink). A pid-based name is guessable by any local user.
fn fresh_scratch_dir() -> Result<Scratch, CliError> {
    use std::os::unix::fs::DirBuilderExt;
    for _ in 0..8 {
        let nonce = SecretBytes::try_random(8)
            .map_err(|e| CliError::failure(format!("entropy failure: {e}"), None))?;
        let hex: String = nonce.with_exposed(|b| b.iter().map(|x| format!("{x:02x}")).collect());
        let path = std::env::temp_dir().join(format!("envholster-merge-{hex}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(Scratch(path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(CliError::from(e)),
        }
    }
    Err(CliError::failure(
        "could not create a fresh merge scratch directory",
        None,
    ))
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The fields of one record a branch could have changed, compared as a
/// whole: a metadata-only, mode, or rotation-state edit is as real a change
/// as a new value and must merge (or conflict) the same way. `created_at`
/// and `updated_at` stay out of the comparison — they are wall-clock
/// bookkeeping two machines stamp differently for the same logical change —
/// but taking a side copies them anyway, because the whole record moves.
#[derive(PartialEq)]
struct RecordSnapshot {
    value: Zeroizing<Vec<u8>>,
    mode: SecretMode,
    guarantee: Guarantee,
    rotated_at: i64,
    rotate_after: Option<i64>,
    needs_rotation: bool,
    metadata: BTreeMap<String, String>,
}

fn snapshot(record: &SecretRecord) -> RecordSnapshot {
    RecordSnapshot {
        value: record.value.with_exposed(|b| Zeroizing::new(b.to_vec())),
        mode: record.mode,
        guarantee: record.guarantee,
        rotated_at: record.rotated_at,
        rotate_after: record.rotate_after,
        needs_rotation: record.needs_rotation,
        metadata: record.metadata.clone(),
    }
}

/// One side's records, snapshotted for the three-way comparison.
type Records = BTreeMap<(CellId, String), RecordSnapshot>;

fn open_side(scratch: &Path, label: &str, source: &Path) -> Result<Vault, CliError> {
    let dir = scratch.join(label);
    create_secret_dir(&dir)?;
    let copy = dir.join(VAULT_FILENAME);
    std::fs::copy(source, &copy)?;
    Vault::open(&copy).map_err(|e| {
        CliError::from(e).with_next(format!(
            "the {label} side ({}) is not a readable vault",
            source.display()
        ))
    })
}

fn unlock_side(session: &mut Session, vault: &mut Vault) -> Result<(), CliError> {
    for status in vault.cells() {
        if status.unlocked {
            continue;
        }
        session.unlock(vault, &status.id).map_err(|e| {
            CliError::new(
                "MERGE_CELL_LOCKED",
                EXIT_FAILURE,
                format!(
                    "cannot merge tier {} cell {}:{} without its identity ({})",
                    status.id.tier.as_u8(),
                    status.id.env.as_str(),
                    status.id.tier.as_u8(),
                    e.message
                ),
                Some(
                    "connect the hardware token or supply --identity, then re-run the merge"
                        .to_owned(),
                ),
            )
        })?;
    }
    Ok(())
}

fn records_of(vault: &Vault) -> Result<Records, CliError> {
    let mut out = Records::new();
    for meta in vault.list() {
        let cell = CellId {
            env: meta.env.clone(),
            tier: meta.tier,
        };
        let record = vault
            .get_secret(&cell, &meta.name)
            .map_err(CliError::from)?;
        out.insert((cell, meta.name.clone()), snapshot(record));
    }
    Ok(out)
}

fn clone_record(record: &SecretRecord) -> Result<SecretRecord, CliError> {
    let value = record
        .value
        .with_exposed(SecretBytes::try_from_slice)
        .map_err(|e| CliError::failure(format!("locked allocation failed: {e}"), None))?;
    Ok(SecretRecord {
        value,
        mode: record.mode,
        guarantee: record.guarantee,
        created_at: record.created_at,
        updated_at: record.updated_at,
        rotated_at: record.rotated_at,
        rotate_after: record.rotate_after,
        needs_rotation: record.needs_rotation,
        metadata: record.metadata.clone(),
    })
}

pub fn run(
    session: &mut Session,
    base: &Path,
    ours: &Path,
    theirs: &Path,
) -> Result<i32, CliError> {
    let scratch = fresh_scratch_dir()?;
    // A blob parked by an earlier, abandoned merge must never be handed to
    // this one's blob driver.
    let side_dir = merge_side_dir();
    if let Some(dir) = &side_dir {
        clear_side_dir(dir);
    }

    // git hands an EMPTY %O when the file did not exist in the merge base
    // (both branches created it): every record is then "added" on its side.
    let mut base_vault = if std::fs::metadata(base).map(|m| m.len()).unwrap_or(0) == 0 {
        None
    } else {
        Some(open_side(&scratch.0, "base", base)?)
    };
    let mut ours_vault = open_side(&scratch.0, "ours", ours)?;
    let mut theirs_vault = open_side(&scratch.0, "theirs", theirs)?;

    // Lineage first, before any unlock: three files that do not descend from
    // the same created vault (same UUID) are not branches of one history,
    // and "merging" them would splice unrelated secrets together.
    let ours_uuid = ours_vault.uuid();
    if theirs_vault.uuid() != ours_uuid
        || base_vault.as_ref().is_some_and(|b| b.uuid() != ours_uuid)
    {
        return Err(CliError::failure(
            "cannot merge: these files are not branches of the same vault (their vault UUIDs \
             differ)"
                .to_owned(),
            Some(
                "keep one side (git checkout --ours/--theirs secrets.holster) and carry any \
                 values over with 'envholster set'"
                    .to_owned(),
            ),
        ));
    }

    // Recipient sets are trust decisions, not mergeable data: a recipient
    // enrolled on one branch can read every future generation, so taking it
    // silently would grant access nobody on this side approved. Any
    // difference is a conflict resolved by choosing a side and enrolling
    // deliberately.
    let ours_ids: BTreeSet<&str> = ours_vault
        .recipients()
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    let theirs_ids: BTreeSet<&str> = theirs_vault
        .recipients()
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    if ours_ids != theirs_ids {
        for entry in theirs_vault.recipients() {
            if !ours_ids.contains(entry.id.as_str()) {
                eprintln!(
                    "CONFLICT: recipient {} ({}) is enrolled on their side only",
                    entry.id.as_str(),
                    entry.label
                );
            }
        }
        for entry in ours_vault.recipients() {
            if !theirs_ids.contains(entry.id.as_str()) {
                eprintln!(
                    "CONFLICT: recipient {} ({}) is enrolled on our side only",
                    entry.id.as_str(),
                    entry.label
                );
            }
        }
        eprintln!(
            "merge-driver: the recipient sets differ; resolve by choosing a side (git checkout \
             --ours/--theirs secrets.holster) and enrolling the missing recipient deliberately \
             with 'envholster recipient add'"
        );
        return Ok(EXIT_FAILURE);
    }

    if let Some(v) = base_vault.as_mut() {
        unlock_side(session, v)?;
    }
    unlock_side(session, &mut ours_vault)?;
    unlock_side(session, &mut theirs_vault)?;

    let base_records = match &base_vault {
        Some(v) => records_of(v)?,
        None => Records::new(),
    };
    let ours_records = records_of(&ours_vault)?;
    let theirs_records = records_of(&theirs_vault)?;

    let mut keys: Vec<(CellId, String)> = ours_records
        .keys()
        .chain(theirs_records.keys())
        .chain(base_records.keys())
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();

    let mut conflicts: Vec<String> = Vec::new();
    let mut take_theirs: Vec<(CellId, String)> = Vec::new();
    let mut remove: Vec<(CellId, String)> = Vec::new();
    for key in &keys {
        let b = base_records.get(key);
        let o = ours_records.get(key);
        let t = theirs_records.get(key);
        if o == t {
            continue; // same on both sides (or absent on both)
        }
        if t == b {
            continue; // only ours changed: ours stands
        }
        if o == b {
            // Only theirs changed: take it.
            match t {
                Some(_) => take_theirs.push(key.clone()),
                None => remove.push(key.clone()),
            }
            continue;
        }
        conflicts.push(format!("{}:{}", key.0.env.as_str(), key.1));
    }
    drop(base_records);
    drop(ours_records);
    drop(theirs_records);

    if !conflicts.is_empty() {
        for c in &conflicts {
            eprintln!("CONFLICT: {c} changed on both sides");
        }
        eprintln!(
            "merge-driver: {} conflict(s); resolve by choosing a side (git checkout --ours/--theirs \
             secrets.holster) and setting the value again with 'envholster set'",
            conflicts.len()
        );
        return Ok(EXIT_FAILURE);
    }

    for (cell, name) in &take_theirs {
        let record = clone_record(
            theirs_vault
                .get_secret(cell, name)
                .map_err(CliError::from)?,
        )?;
        session.unlock(&mut ours_vault, cell).ok();
        // The WHOLE record moves: remove-then-add carries their side's mode,
        // guarantee, rotation state, metadata, and timestamps, where
        // edit_secret would keep ours and replace only the value.
        if ours_vault.get_secret(cell, name).is_ok() {
            ours_vault
                .remove_secret(cell, name)
                .map_err(CliError::from)?;
        }
        ours_vault
            .add_secret(cell, name, record)
            .map_err(CliError::from)?;
    }
    for (cell, name) in &remove {
        ours_vault
            .remove_secret(cell, name)
            .map_err(CliError::from)?;
    }
    ours_vault.save().map_err(CliError::from)?;

    // Hand git the merged file, and refresh the committed recovery blob when
    // the driver runs where it lives (git runs drivers at the repo root).
    let merged = scratch.0.join("ours").join(VAULT_FILENAME);
    std::fs::copy(&merged, ours)?;
    let blob_src = scratch.0.join("ours").join(RECOVERY_FILENAME);
    let blob_dst = Path::new(RECOVERY_FILENAME);
    if blob_src.is_file() && Path::new(VAULT_FILENAME).exists() {
        std::fs::copy(&blob_src, blob_dst)?;
    }
    // Park the regenerated blob for the blob driver (see `merge_side_dir`).
    if let (Some(dir), true) = (&side_dir, blob_src.is_file()) {
        create_secret_dir(dir)?;
        let parked = dir.join(format!("{}.recovery.age", uuid_string(&ours_uuid)));
        let _ = std::fs::remove_file(&parked);
        write_secret_file_exclusive(&parked, &std::fs::read(&blob_src)?)?;
    }
    eprintln!(
        "merge-driver: merged {} record(s) from their side, removed {}, {} conflict(s)",
        take_theirs.len(),
        remove.len(),
        conflicts.len()
    );
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The three-way comparison must see every field a branch could have
    /// changed — a metadata-only or rotation-flag-only edit is a change —
    /// while the wall-clock bookkeeping stamps must NOT count, or two
    /// machines storing the same logical change would always conflict.
    #[test]
    fn snapshot_compares_the_whole_record_but_not_the_clock() {
        let a = record(b"v");
        assert!(snapshot(&a) == snapshot(&record(b"v")));

        let mut stamped = record(b"v");
        stamped.created_at = 99;
        stamped.updated_at = 99;
        assert!(snapshot(&a) == snapshot(&stamped));

        let mut metadata_edit = record(b"v");
        metadata_edit
            .metadata
            .insert("owner".to_owned(), "payments".to_owned());
        assert!(snapshot(&a) != snapshot(&metadata_edit));

        let mut flagged = record(b"v");
        flagged.needs_rotation = true;
        assert!(snapshot(&a) != snapshot(&flagged));

        let mut rotated = record(b"v");
        rotated.rotated_at = 99;
        assert!(snapshot(&a) != snapshot(&rotated));

        let mut deadline = record(b"v");
        deadline.rotate_after = Some(3600);
        assert!(snapshot(&a) != snapshot(&deadline));

        assert!(snapshot(&a) != snapshot(&record(b"w")));
    }
}
