//! The vault (frozen API: plan/04-contracts §4.3; byte mechanisms:
//! plan/02-envelope).
//!
//! Frozen invariants: NO nonce field exists on `Vault` or any cell struct — a
//! fresh 24-byte nonce is drawn via `getrandom::fill` immediately before each
//! encrypt; a stored nonce is never an encryption input (c1; the parsed
//! header's nonce is decrypt input only). Body bytes touch only locked
//! buffers (HB1). `save` re-encrypts cells with a fresh nonce each, bumps
//! generation, writes vault THEN recovery blob atomically (0600/0700),
//! failing closed as `RecoveryLockstep` (D6).
//!
//! Save/AAD consequence (plan/02 §3–§4, §9): the generation counter is part
//! of the header core, and the header core is every cell's AAD — so every
//! persisted body must be re-encrypted under the new core on every save
//! ("each body changes entirely on every save — by design"). A locked cell
//! cannot be carried across a save: its old ciphertext would fail decryption
//! for every legitimate opener under the new AAD. `save` therefore requires
//! every persisted cell to be unlocked, surfacing `CellLocked` otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use envholster_mem::SecretBytes;
use zeroize::Zeroizing;

use crate::commit::{dek_commitment, verify_dek_commitment};
use crate::constants::{DEK_LEN, DIR_MODE_SECRET, FILE_MODE_SECRET, NONCE_LEN, TAG_LEN};
use crate::envelope::{cell_aad, CellHeader, CellPayload, Envelope, HeaderCore};
use crate::error::CoreError;
use crate::hb1;
use crate::record::{CellId, CellStatus, SecretMeta, SecretRecord, VaultUuid};
use crate::recovery::{self, SnapshotCell};
use crate::types::{
    EnvName, EnvSelector, Identity, RecipientClass, RecipientEntry, RecipientId, RecipientKind,
    Tier,
};
use crate::ui::WrapContext;
use crate::wrap::{unwrap_cell_dek, wrap_dek, CellWrap, DekBytes};

/// In-memory state of one unlocked cell. The DEK lives in locked memory
/// (`SecretBytes`); the `Zeroizing` staging form exists only transiently at
/// the age boundary (plan/03 window 3; wrap.rs).
struct UnlockedCell {
    dek: SecretBytes,
    /// HMAC-SHA-256(DEK, "envholster-v1-commit") — recomputed on DEK rotation.
    commitment: [u8; 32],
    /// One single-recipient age blob per eligible recipient, sorted by id.
    wraps: Vec<(RecipientId, Vec<u8>)>,
    records: BTreeMap<String, SecretRecord>,
}

pub struct Vault {
    path: PathBuf,
    /// Sidecar advisory flock (`<vault>.lock`), held for the Vault's lifetime
    /// — the open-modify-save window (plan/02 §8). RAII: released on drop.
    /// A sidecar (not the vault file itself) because the vault inode is
    /// replaced by every atomic rename.
    _lock_file: File,
    /// The exact persisted image (mirrors disk between saves). Its header
    /// core is the decrypt-side AAD, so it is NEVER mutated in place —
    /// logical changes accumulate in `recipients`/`unlocked` and become the
    /// next envelope at save.
    envelope: Envelope,
    /// Current logical recipient set (starts as the envelope's).
    recipients: Vec<RecipientEntry>,
    /// Unlocked cells, keyed (env × tier). Lazily created cells (plan/02 §2)
    /// live only here until the save that first persists them.
    unlocked: BTreeMap<CellId, UnlockedCell>,
    /// Test-only clock override for the recovery blob's `saved_at` — the
    /// golden-fixture generator (a unit test) pins it; production code never
    /// sets it and `save` uses the real clock.
    saved_at_override: Option<i64>,
}

impl Vault {
    pub const SCHEMA: u32 = 1;

    /// Requires exactly one Recovery-class entry (D6) and enforces the wrap
    /// matrix (G-A). Writes the initial (cell-less) vault at generation 1.
    pub fn create(
        path: &Path,
        recipients: Vec<RecipientEntry>,
        ctx: &WrapContext,
    ) -> Result<Self, CoreError> {
        validate_recipients(&recipients)?;
        // No cells exist yet, so there is no DEK to wrap; `ctx` is part of
        // the frozen signature and first exercised by `unlock_cell`.
        let _ = ctx;
        if path.exists() {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("vault already exists at {}", path.display()),
            )));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(DIR_MODE_SECRET)
                    .create(parent)?;
            }
        }
        let lock_file = acquire_lock(path)?;
        let envelope = Envelope {
            core: HeaderCore {
                generation: 0,
                vault_uuid: random_uuid()?,
                recipients: recipients.clone(),
                cells: Vec::new(),
            },
            payloads: Vec::new(),
        };
        let mut vault = Vault {
            path: path.to_owned(),
            _lock_file: lock_file,
            envelope,
            recipients,
            unlocked: BTreeMap::new(),
            saved_at_override: None,
        };
        vault.save()?; // generation 0 → 1; first atomic write (vault + blob)
        Ok(vault)
    }

    /// Parses the plaintext header only; takes the advisory flock held across
    /// open-modify-save. No identity is touched and no cell is unlocked.
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        let lock_file = acquire_lock(path)?;
        let bytes = std::fs::read(path)?;
        let envelope = Envelope::parse(&bytes)?;
        let recipients = envelope.core.recipients.clone();
        Ok(Vault {
            path: path.to_owned(),
            _lock_file: lock_file,
            envelope,
            recipients,
            unlocked: BTreeMap::new(),
            saved_at_override: None,
        })
    }

    /// The recipient list from the plaintext header, WITHOUT taking the
    /// advisory flock. For read-only questions — "which of this machine's
    /// identities can open this vault?", "does it have a passphrase?" — asked
    /// while a daemon (or the menu-bar app) legitimately holds the lock. The
    /// file is only ever replaced atomically (temp + rename), so a torn read is
    /// impossible; nothing here can modify the vault, so nothing needs the
    /// lock. No identity is touched and no cell is unlocked.
    pub fn peek_recipients(path: &Path) -> Result<Vec<RecipientEntry>, CoreError> {
        let bytes = std::fs::read(path)?;
        let envelope = Envelope::parse(&bytes)?;
        Ok(envelope.core.recipients)
    }

    /// Per-identity unwrap loop (c21), commitment check (c2), then in-place
    /// AEAD decrypt into locked memory. Residency/TTL policy is
    /// plan/05-daemon's.
    ///
    /// Cells are lazy (plan/02 §2): unlocking a cell that does not exist yet
    /// creates it — fresh locked DEK, wraps to every eligible recipient (the
    /// wrap matrix decides eligibility), zero records. This is the only
    /// entry point carrying the `WrapContext` a fresh DEK's wraps need.
    pub fn unlock_cell(
        &mut self,
        cell: &CellId,
        identities: &[Identity],
        ctx: &WrapContext,
    ) -> Result<(), CoreError> {
        if self.unlocked.contains_key(cell) {
            return Ok(());
        }

        let state = match self.cell_index(cell) {
            Some(index) => self.decrypt_persisted_cell(index, cell, identities, ctx, false)?,
            None => {
                // Lazy cell creation.
                let dek = SecretBytes::try_random(DEK_LEN)?;
                let commitment = dek.with_exposed(dek_commitment);
                let staged = stage_dek(&dek);
                let mut wraps = Vec::new();
                for entry in self
                    .recipients
                    .iter()
                    .filter(|e| is_eligible(e, &cell.env, cell.tier))
                {
                    wraps.push((entry.id.clone(), wrap_dek(&staged, entry, ctx)?));
                }
                drop(staged); // Zeroizing
                wraps.sort_by(|a, b| a.0.cmp(&b.0));
                UnlockedCell {
                    dek,
                    commitment,
                    wraps,
                    records: BTreeMap::new(),
                }
            }
        };
        self.unlocked.insert(cell.clone(), state);
        Ok(())
    }

    /// Zeroizes DEK + records (every `SecretBytes` drop zeroizes its locked
    /// buffer). A lazily created, never-persisted cell simply ceases to exist.
    pub fn lock_cell(&mut self, cell: &CellId) {
        self.unlocked.remove(cell);
    }

    /// Re-encrypts every persisted cell (fresh nonce each — see the module
    /// doc for why "dirty" is the whole vault under a generation-covering
    /// AAD), bumps generation, writes vault THEN recovery blob atomically;
    /// fails closed as `RecoveryLockstep` (D6). Record-less cells are dropped
    /// (occupied-cell topology, plan/02 §2).
    pub fn save(&mut self) -> Result<(), CoreError> {
        validate_recipients(&self.recipients)?;
        for header in &self.envelope.core.cells {
            let id = CellId {
                env: header.env.clone(),
                tier: header.tier,
            };
            if !self.unlocked.contains_key(&id) {
                return Err(CoreError::CellLocked {
                    env: id.env.as_str().to_owned(),
                    tier: id.tier.as_u8(),
                });
            }
        }

        let live: Vec<CellId> = self
            .unlocked
            .iter()
            .filter(|(_, cell)| !cell.records.is_empty())
            .map(|(id, _)| id.clone())
            .collect();

        let generation = self
            .envelope
            .core
            .generation
            .checked_add(1)
            .ok_or_else(|| CoreError::HeaderParse {
                reason: "generation counter overflow".to_owned(),
            })?;

        // Pass 1: headers. Nonces are drawn fresh here (c1/c19) — they must
        // exist before the core is serialized because the core (including
        // each nonce) is the AAD; the LOCAL `nonces` copies below — never a
        // field read back from a struct — are the encryption inputs.
        let mut headers = Vec::with_capacity(live.len());
        let mut nonces: Vec<[u8; NONCE_LEN]> = Vec::with_capacity(live.len());
        let mut bodies: Vec<SecretBytes> = Vec::with_capacity(live.len());
        for id in &live {
            let cell = &self.unlocked[id];
            validate_cell_wraps(id, &cell.wraps, &self.recipients)?;
            let body = hb1::encode(&cell.records, id.tier)?;
            let ct_len = u32::try_from(body.len()).map_err(|_| CoreError::HeaderParse {
                reason: "cell body exceeds u32::MAX bytes".to_owned(),
            })?;
            let mut nonce = [0u8; NONCE_LEN];
            getrandom::fill(&mut nonce)?;
            headers.push(CellHeader {
                env: id.env.clone(),
                tier: id.tier,
                commitment: cell.commitment,
                nonce,
                ct_len,
                wraps: cell.wraps.clone(),
            });
            nonces.push(nonce);
            bodies.push(body);
        }

        let core = HeaderCore {
            generation,
            vault_uuid: self.envelope.core.vault_uuid,
            recipients: self.recipients.clone(),
            cells: headers,
        };
        let core_bytes = core.canonical_bytes();

        // Pass 2: in-place AEAD inside the locked HB1 buffers (plan/03
        // window 2); the buffer holds ciphertext afterwards — not secret —
        // and is copied out for the envelope.
        let mut payloads = Vec::with_capacity(live.len());
        for (i, id) in live.iter().enumerate() {
            let cell = &self.unlocked[id];
            let aad = cell_aad(&core_bytes, &id.env, id.tier);
            let tag = cell
                .dek
                .with_exposed(|key| {
                    bodies[i].with_exposed_mut(|plaintext| {
                        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
                        cipher.encrypt_in_place_detached(
                            XNonce::from_slice(&nonces[i]),
                            &aad,
                            plaintext,
                        )
                    })
                })
                .map_err(|_| CoreError::AeadFailed {
                    env: id.env.as_str().to_owned(),
                    tier: id.tier.as_u8(),
                })?;
            let mut tag_bytes = [0u8; TAG_LEN];
            tag_bytes.copy_from_slice(&tag);
            payloads.push(CellPayload {
                tag: tag_bytes,
                body: bodies[i].with_exposed(|b| b.to_vec()),
            });
        }

        let envelope = Envelope { core, payloads };

        // Recovery blob for the identical store snapshot, same generation
        // (D6, plan/02 §7; RECOVERY-SPEC §2): the canonical JSON is assembled
        // in a locked buffer and streamed into a true armored age Encryptor
        // to the Recovery recipient ONLY. Fully prepared BEFORE either rename
        // (ENVELOPE-SPEC §8.1 step 8 / Appendix A.11), so any preparation
        // failure aborts the save with both files untouched.
        let lockstep = |error: CoreError| match error {
            already @ CoreError::RecoveryLockstep { .. } => already,
            other => CoreError::RecoveryLockstep {
                reason: other.to_string(),
            },
        };
        let saved_at = self.saved_at_override.unwrap_or_else(now_epoch);
        let blob_bytes = self
            .prepare_recovery_blob(&live, generation, saved_at)
            .map_err(lockstep)?;
        let vault_bytes = envelope.to_bytes();
        let recovery_path = recovery::recovery_path_for(&self.path);

        // Durable replace, two-phase: write + fsync both temp files, then
        // rename the vault FIRST, then the blob (plan/02 §8). A failure
        // between the renames is the drift window `doctor` exists for; the
        // next successful save restores lockstep.
        let vault_staged = StagedWrite::stage(&self.path, &vault_bytes)?;
        let blob_staged = StagedWrite::stage(&recovery_path, &blob_bytes)
            .map_err(|e| lockstep(CoreError::Io(e)))?;
        vault_staged.commit()?; // on failure both temp files are cleaned up
        self.envelope = envelope; // the vault file IS the new generation now
        blob_staged
            .commit()
            .map_err(|e| lockstep(CoreError::Io(e)))?;
        Ok(())
    }

    /// The armored recovery-blob bytes for the given persisted snapshot
    /// (`live` = the sorted cell ids `save` is persisting; every one is
    /// unlocked). Ciphertext out; plaintext only ever in locked buffers
    /// (plan/03 window 5).
    fn prepare_recovery_blob(
        &self,
        live: &[CellId],
        generation: u64,
        saved_at: i64,
    ) -> Result<Vec<u8>, CoreError> {
        let cells: Vec<SnapshotCell<'_>> = live
            .iter()
            .map(|id| SnapshotCell {
                env: &id.env,
                tier: id.tier,
                records: &self.unlocked[id].records,
            })
            .collect();
        let uuid_text = crate::envelope::uuid_to_string(&self.envelope.core.vault_uuid);
        let json = recovery::assemble_store_json(&cells, generation, saved_at, &uuid_text)?;
        recovery::encrypt_store_json(&json, &self.recipients)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn generation(&self) -> u64 {
        self.envelope.core.generation
    }

    pub fn uuid(&self) -> VaultUuid {
        self.envelope.core.vault_uuid
    }

    /// Persisted and pending cells, sorted (env asc, tier asc).
    /// `record_count` is 0 for locked cells — the count lives inside the
    /// ciphertext. `floor` = weakest wrapped recipient class (G-A).
    pub fn cells(&self) -> Vec<CellStatus> {
        let mut out: BTreeMap<CellId, CellStatus> = BTreeMap::new();
        for header in &self.envelope.core.cells {
            let id = CellId {
                env: header.env.clone(),
                tier: header.tier,
            };
            out.insert(
                id.clone(),
                CellStatus {
                    id,
                    unlocked: false,
                    record_count: 0,
                    floor: wrap_floor(&header.wraps, &self.recipients),
                },
            );
        }
        for (id, cell) in &self.unlocked {
            out.insert(
                id.clone(),
                CellStatus {
                    id: id.clone(),
                    unlocked: true,
                    record_count: cell.records.len(),
                    floor: wrap_floor(&cell.wraps, &self.recipients),
                },
            );
        }
        out.into_values().collect()
    }

    // --- secrets — target cell must be unlocked, else `CellLocked` ---

    /// Rejects caller metadata keys under `METADATA_RESERVED_PREFIX`
    /// (`InvalidName`) and duplicate names.
    pub fn add_secret(
        &mut self,
        cell: &CellId,
        name: &str,
        record: SecretRecord,
    ) -> Result<(), CoreError> {
        hb1::validate_secret_name(name)?;
        for key in record.metadata.keys() {
            if key.starts_with(crate::constants::METADATA_RESERVED_PREFIX) {
                return Err(CoreError::InvalidName {
                    name: key.clone(),
                    reason: format!(
                        "metadata keys under {:?} are reserved for envholster",
                        crate::constants::METADATA_RESERVED_PREFIX
                    ),
                });
            }
        }
        let state = self.unlocked_mut(cell)?;
        if state.records.contains_key(name) {
            return Err(CoreError::InvalidName {
                name: name.to_owned(),
                reason: "secret already exists in this cell; use edit_secret or rotate_secret"
                    .to_owned(),
            });
        }
        state.records.insert(name.to_owned(), record);
        Ok(())
    }

    pub fn get_secret(&self, cell: &CellId, name: &str) -> Result<&SecretRecord, CoreError> {
        self.unlocked_ref(cell)?
            .records
            .get(name)
            .ok_or_else(|| CoreError::SecretNotFound(name.to_owned()))
    }

    /// Bumps `updated_at`.
    pub fn edit_secret(
        &mut self,
        cell: &CellId,
        name: &str,
        value: SecretBytes,
    ) -> Result<(), CoreError> {
        let record = self
            .unlocked_mut(cell)?
            .records
            .get_mut(name)
            .ok_or_else(|| CoreError::SecretNotFound(name.to_owned()))?;
        record.value = value;
        record.updated_at = now_epoch();
        Ok(())
    }

    /// Bumps `rotated_at`, clears `needs_rotation`; the distinct audit event
    /// lands with the P1 audit log.
    pub fn rotate_secret(
        &mut self,
        cell: &CellId,
        name: &str,
        value: SecretBytes,
    ) -> Result<(), CoreError> {
        let record = self
            .unlocked_mut(cell)?
            .records
            .get_mut(name)
            .ok_or_else(|| CoreError::SecretNotFound(name.to_owned()))?;
        record.value = value;
        record.rotated_at = now_epoch();
        record.needs_rotation = false;
        Ok(())
    }

    pub fn remove_secret(&mut self, cell: &CellId, name: &str) -> Result<(), CoreError> {
        self.unlocked_mut(cell)?
            .records
            .remove(name)
            .map(|_| ()) // dropped record zeroizes its value
            .ok_or_else(|| CoreError::SecretNotFound(name.to_owned()))
    }

    /// Unlocked cells only; the CLI joins the manifest for the rest.
    pub fn list(&self) -> Vec<SecretMeta> {
        let mut out = Vec::new();
        for (id, cell) in &self.unlocked {
            for (name, record) in &cell.records {
                out.push(SecretMeta {
                    name: name.clone(),
                    env: id.env.clone(),
                    tier: id.tier,
                    mode: record.mode,
                    guarantee: record.guarantee,
                    needs_rotation: record.needs_rotation,
                    rotated_at: record.rotated_at,
                    rotate_after: record.rotate_after,
                });
            }
        }
        out
    }

    // --- recipients ---

    pub fn recipients(&self) -> &[RecipientEntry] {
        &self.recipients
    }

    /// Wraps the existing DEK of every reachable cell (cells must be
    /// unlockable with the supplied identities/ctx). Enrollment that violates
    /// the wrap matrix (a Software entry claiming max_tier ≥ 2) is
    /// `ForbiddenWrap` before anything is touched.
    pub fn add_recipient(
        &mut self,
        entry: RecipientEntry,
        identities: &[Identity],
        ctx: &WrapContext,
    ) -> Result<(), CoreError> {
        if self.recipients.iter().any(|r| r.id == entry.id) {
            return Err(CoreError::InvalidName {
                name: entry.id.as_str().to_owned(),
                reason: "recipient is already enrolled".to_owned(),
            });
        }
        let mut candidate = self.recipients.clone();
        candidate.push(entry.clone());
        validate_recipients(&candidate)?;

        let reachable: Vec<CellId> = self
            .all_cell_ids()
            .into_iter()
            .filter(|id| is_eligible(&entry, &id.env, id.tier))
            .collect();
        for id in &reachable {
            self.unlock_cell(id, identities, ctx)?;
        }
        for id in &reachable {
            let staged = stage_dek(&self.unlocked[id].dek);
            let blob = wrap_dek(&staged, &entry, ctx)?;
            drop(staged);
            let cell = self.unlocked.get_mut(id).expect("just unlocked");
            cell.wraps.push((entry.id.clone(), blob));
            cell.wraps.sort_by(|a, b| a.0.cmp(&b.0));
        }
        self.recipients = candidate;
        Ok(())
    }

    /// Rotates every affected cell's DEK AND flags every reachable record
    /// `needs_rotation` (c22 — rotation ≠ revocation; git history stays
    /// decryptable by the removed recipient). Re-wrap to a remaining scrypt
    /// recipient re-prompts via `ctx`. Removing the sole Recovery entry is
    /// refused (D6).
    pub fn remove_recipient(
        &mut self,
        id: &RecipientId,
        identities: &[Identity],
        ctx: &WrapContext,
    ) -> Result<(), CoreError> {
        let position = self
            .recipients
            .iter()
            .position(|r| r.id == *id)
            .ok_or_else(|| CoreError::RecipientNotFound(id.as_str().to_owned()))?;
        if self.recipients[position].class == RecipientClass::Recovery {
            return Err(CoreError::RecoveryRecipientCount { found: 0 });
        }

        // Every cell the removed recipient could unwrap (c22).
        let affected: Vec<CellId> = self
            .all_cell_ids()
            .into_iter()
            .filter(|cid| self.cell_wraps(cid).iter().any(|(rid, _)| rid == id))
            .collect();
        for cid in &affected {
            self.unlock_cell(cid, identities, ctx)?;
        }
        self.recipients.remove(position);

        for cid in &affected {
            let dek = SecretBytes::try_random(DEK_LEN)?;
            let commitment = dek.with_exposed(dek_commitment);
            let staged = stage_dek(&dek);
            let mut wraps = Vec::new();
            for entry in self
                .recipients
                .iter()
                .filter(|e| is_eligible(e, &cid.env, cid.tier))
            {
                wraps.push((entry.id.clone(), wrap_dek(&staged, entry, ctx)?));
            }
            drop(staged);
            wraps.sort_by(|a, b| a.0.cmp(&b.0));
            let cell = self.unlocked.get_mut(cid).expect("just unlocked");
            cell.dek = dek;
            cell.commitment = commitment;
            cell.wraps = wraps;
            for record in cell.records.values_mut() {
                record.needs_rotation = true;
            }
        }
        Ok(())
    }

    /// Re-keys one cell's DEK: fresh locked DEK, fresh commitment, re-wrapped
    /// to every currently eligible recipient (wrap matrix, G-A). The cell is
    /// unlocked first with the supplied identities. Records are untouched —
    /// DEK re-keying is not value rotation, so `needs_rotation` is NOT set
    /// (that flag belongs to `remove_recipient`'s exposure semantics, c22).
    ///
    /// Stage-C addition backing the P0 `rotate-dek` command (plan/07 §7.5,
    /// c42); not part of the §4.3 frozen method set. The caller persists via
    /// `save` and must then re-prove recovery (`recovery test` — c42).
    pub fn rotate_cell_dek(
        &mut self,
        cell: &CellId,
        identities: &[Identity],
        ctx: &WrapContext,
    ) -> Result<(), CoreError> {
        self.unlock_cell(cell, identities, ctx)?;
        let dek = SecretBytes::try_random(DEK_LEN)?;
        let commitment = dek.with_exposed(dek_commitment);
        let staged = stage_dek(&dek);
        let mut wraps = Vec::new();
        for entry in self
            .recipients
            .iter()
            .filter(|e| is_eligible(e, &cell.env, cell.tier))
        {
            wraps.push((entry.id.clone(), wrap_dek(&staged, entry, ctx)?));
        }
        drop(staged);
        wraps.sort_by(|a, b| a.0.cmp(&b.0));
        let state = self.unlocked.get_mut(cell).expect("just unlocked");
        state.dek = dek;
        state.commitment = commitment;
        state.wraps = wraps;
        Ok(())
    }

    fn decrypt_persisted_cell(
        &self,
        index: usize,
        cell: &CellId,
        identities: &[Identity],
        ctx: &WrapContext,
        recovery_only: bool,
    ) -> Result<UnlockedCell, CoreError> {
        let header = &self.envelope.core.cells[index];
        let payload = &self.envelope.payloads[index];
        let aead_failed = || CoreError::AeadFailed {
            env: cell.env.as_str().to_owned(),
            tier: cell.tier.as_u8(),
        };

        let wraps_view: Vec<_> = header
            .wraps
            .iter()
            .filter(|(id, _)| {
                !recovery_only
                    || self
                        .envelope
                        .core
                        .recipients
                        .iter()
                        .any(|r| r.id == *id && r.class == RecipientClass::Recovery)
            })
            .map(|(id, blob)| CellWrap {
                is_scrypt: self
                    .envelope
                    .core
                    .recipients
                    .iter()
                    .any(|r| r.id == *id && matches!(r.kind, RecipientKind::Scrypt { .. })),
                blob,
            })
            .collect();
        let dek: DekBytes = unwrap_cell_dek(cell, &wraps_view, identities, ctx)?;

        // ONE error for commitment AND tag failure (c2).
        if !verify_dek_commitment(&dek[..], &header.commitment) {
            return Err(aead_failed());
        }

        // The decrypt-side AAD is the PERSISTED core — the exact
        // bytes the ciphertext was authenticated under.
        let core_bytes = self.envelope.core.canonical_bytes();
        let aad = cell_aad(&core_bytes, &cell.env, cell.tier);
        let mut buf = SecretBytes::try_with_capacity(payload.body.len())?;
        buf.with_exposed_mut(|b| {
            b.copy_from_slice(&payload.body);
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&dek[..]));
            cipher.decrypt_in_place_detached(
                XNonce::from_slice(&header.nonce),
                &aad,
                b,
                Tag::from_slice(&payload.tag),
            )
        })
        .map_err(|_| aead_failed())?;

        let records = hb1::parse(&buf, cell.tier)?;
        Ok(UnlockedCell {
            dek: SecretBytes::try_from_slice(&dek[..])?,
            commitment: header.commitment,
            wraps: header.wraps.clone(),
            records,
        })
    }

    pub(crate) fn persisted_recovery_recipient(&self) -> Result<&RecipientEntry, CoreError> {
        let mut entries = self
            .envelope
            .core
            .recipients
            .iter()
            .filter(|r| r.class == RecipientClass::Recovery);
        let entry = entries.next();
        if entry.is_none() || entries.next().is_some() {
            return Err(CoreError::RecoveryLockstep {
                reason: "vault must contain exactly one recovery recipient".to_owned(),
            });
        }
        Ok(entry.expect("checked above"))
    }

    pub(crate) fn recovery_records(
        &self,
        identities: &[Identity],
        ctx: &WrapContext,
    ) -> Result<BTreeMap<CellId, BTreeMap<String, SecretRecord>>, CoreError> {
        // Verification must authenticate persisted ciphertext even when callers
        // have cached or edited unlocked records in memory.
        self.persisted_cells()
            .enumerate()
            .map(|(index, (_, cell))| {
                let state = self.decrypt_persisted_cell(index, &cell, identities, ctx, true)?;
                Ok((cell, state.records))
            })
            .collect()
    }

    // --- internals ---

    /// Persisted cell headers with their ids — used by `recovery_test`
    /// (recovery.rs) to prove the recovery unwrap per cell.
    pub(crate) fn persisted_cells(&self) -> impl Iterator<Item = (&CellHeader, CellId)> {
        self.envelope.core.cells.iter().map(|header| {
            (
                header,
                CellId {
                    env: header.env.clone(),
                    tier: header.tier,
                },
            )
        })
    }

    fn cell_index(&self, cell: &CellId) -> Option<usize> {
        self.envelope
            .core
            .cells
            .iter()
            .position(|c| c.env == cell.env && c.tier == cell.tier)
    }

    /// Wrap list of a cell as currently known: unlocked state wins (it may
    /// carry a rotation), else the persisted header.
    fn cell_wraps(&self, cell: &CellId) -> &[(RecipientId, Vec<u8>)] {
        if let Some(state) = self.unlocked.get(cell) {
            return &state.wraps;
        }
        match self.cell_index(cell) {
            Some(index) => &self.envelope.core.cells[index].wraps,
            None => &[],
        }
    }

    fn all_cell_ids(&self) -> BTreeSet<CellId> {
        let mut ids: BTreeSet<CellId> = self.unlocked.keys().cloned().collect();
        for header in &self.envelope.core.cells {
            ids.insert(CellId {
                env: header.env.clone(),
                tier: header.tier,
            });
        }
        ids
    }

    fn unlocked_ref(&self, cell: &CellId) -> Result<&UnlockedCell, CoreError> {
        self.unlocked
            .get(cell)
            .ok_or_else(|| CoreError::CellLocked {
                env: cell.env.as_str().to_owned(),
                tier: cell.tier.as_u8(),
            })
    }

    fn unlocked_mut(&mut self, cell: &CellId) -> Result<&mut UnlockedCell, CoreError> {
        self.unlocked
            .get_mut(cell)
            .ok_or_else(|| CoreError::CellLocked {
                env: cell.env.as_str().to_owned(),
                tier: cell.tier.as_u8(),
            })
    }
}

/// Golden-fixture generator support (crates/envholster-core/tests/golden/,
/// ENVELOPE-SPEC §11). Test-compiled only: the generator is a unit test, so
/// none of this exists in a shipped binary.
#[cfg(test)]
impl Vault {
    /// A vault at generation 0 with NO initial save — the generator drives
    /// `save` itself so a fixture can land at any pinned generation (e.g.
    /// vault-named is generation 1 WITH cells, which `create`'s empty
    /// generation-1 save could never produce).
    pub(crate) fn testing_create_unsaved(
        path: &Path,
        recipients: Vec<RecipientEntry>,
        uuid: VaultUuid,
    ) -> Result<Self, CoreError> {
        validate_recipients(&recipients)?;
        let lock_file = acquire_lock(path)?;
        Ok(Vault {
            path: path.to_owned(),
            _lock_file: lock_file,
            envelope: Envelope {
                core: HeaderCore {
                    generation: 0,
                    vault_uuid: uuid,
                    recipients: recipients.clone(),
                    cells: Vec::new(),
                },
                payloads: Vec::new(),
            },
            recipients,
            unlocked: BTreeMap::new(),
            saved_at_override: None,
        })
    }

    /// Pins the recovery blob's `saved_at` (fixture timestamps are frozen in
    /// ENVELOPE-SPEC §11.3).
    pub(crate) fn testing_set_saved_at(&mut self, saved_at: i64) {
        self.saved_at_override = Some(saved_at);
    }

    /// Inserts a pre-built unlocked cell with caller-supplied wraps — the
    /// vault-tier2 fixture's hardware wrap blob cannot be produced through
    /// `unlock_cell` without the plugin binary. `save` still validates the
    /// wrap set against the matrix.
    pub(crate) fn testing_insert_unlocked_cell(
        &mut self,
        cell: CellId,
        dek: SecretBytes,
        mut wraps: Vec<(RecipientId, Vec<u8>)>,
    ) {
        let commitment = dek.with_exposed(dek_commitment);
        wraps.sort_by(|a, b| a.0.cmp(&b.0));
        self.unlocked.insert(
            cell,
            UnlockedCell {
                dek,
                commitment,
                wraps,
                records: BTreeMap::new(),
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Wrap matrix (G-A) — plan/02 §2
// ---------------------------------------------------------------------------

fn enrolled_max_tier(entry: &RecipientEntry, env: &EnvName) -> Option<Tier> {
    match &entry.enrollment.0 {
        EnvSelector::All { max_tier } => Some(*max_tier),
        EnvSelector::Named(map) => map.get(env).copied(),
    }
}

/// May this recipient be wrapped to cell (env, tier)?
/// recovery: every cell. hardware: enrolled for env at max_tier ≥ tier.
/// software: tier-1 cells of enrolled envs ONLY (G-A).
fn is_eligible(entry: &RecipientEntry, env: &EnvName, tier: Tier) -> bool {
    match entry.class {
        RecipientClass::Recovery => true,
        RecipientClass::Hardware => enrolled_max_tier(entry, env).is_some_and(|m| m >= tier),
        RecipientClass::Software => {
            tier == Tier::Ambient && enrolled_max_tier(entry, env).is_some_and(|m| m >= tier)
        }
    }
}

fn forbidden_wrap(entry: &RecipientEntry, env: &str, tier: Tier) -> CoreError {
    CoreError::ForbiddenWrap {
        recipient: entry.id.as_str().to_owned(),
        class: entry.class,
        env: env.to_owned(),
        tier: tier.as_u8(),
    }
}

/// Recipient-set rules enforced at create/save/add_recipient:
/// exactly one Recovery entry (D6), enrolled `*:3` (plan/02 §3); Software
/// enrollment capped at tier 1 — `ForbiddenWrap`, no override (G-A); no
/// duplicate ids.
fn validate_recipients(recipients: &[RecipientEntry]) -> Result<(), CoreError> {
    for (i, entry) in recipients.iter().enumerate() {
        if recipients[..i].iter().any(|other| other.id == entry.id) {
            return Err(CoreError::InvalidName {
                name: entry.id.as_str().to_owned(),
                reason: "duplicate recipient id".to_owned(),
            });
        }
    }

    let found = recipients
        .iter()
        .filter(|r| r.class == RecipientClass::Recovery)
        .count();
    if found != 1 {
        return Err(CoreError::RecoveryRecipientCount { found });
    }
    let recovery = recipients
        .iter()
        .find(|r| r.class == RecipientClass::Recovery)
        .expect("count checked above");
    if !matches!(
        recovery.enrollment.0,
        EnvSelector::All {
            max_tier: Tier::Critical
        }
    ) {
        return Err(CoreError::InvalidName {
            name: recovery.id.as_str().to_owned(),
            reason: "the recovery recipient must be enrolled *:3 — every environment at max_tier 3"
                .to_owned(),
        });
    }

    for entry in recipients
        .iter()
        .filter(|r| r.class == RecipientClass::Software)
    {
        match &entry.enrollment.0 {
            EnvSelector::All { max_tier } if *max_tier > Tier::Ambient => {
                return Err(forbidden_wrap(entry, "*", *max_tier));
            }
            EnvSelector::Named(map) => {
                for (env, tier) in map {
                    if *tier > Tier::Ambient {
                        return Err(forbidden_wrap(entry, env.as_str(), *tier));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A cell's wrap set must be EXACTLY its eligible recipient set: an
/// ineligible wrap is `ForbiddenWrap` (software on tier ≥ 2 is the G-A hard
/// error, no override); a missing eligible wrap would silently orphan that
/// recipient.
fn validate_cell_wraps(
    id: &CellId,
    wraps: &[(RecipientId, Vec<u8>)],
    recipients: &[RecipientEntry],
) -> Result<(), CoreError> {
    for (rid, _) in wraps {
        let entry =
            recipients
                .iter()
                .find(|e| e.id == *rid)
                .ok_or_else(|| CoreError::HeaderParse {
                    reason: format!(
                        "cell {}:{} wraps unknown recipient {}",
                        id.env.as_str(),
                        id.tier.as_u8(),
                        rid.as_str()
                    ),
                })?;
        if !is_eligible(entry, &id.env, id.tier) {
            return Err(CoreError::ForbiddenWrap {
                recipient: rid.as_str().to_owned(),
                class: entry.class,
                env: id.env.as_str().to_owned(),
                tier: id.tier.as_u8(),
            });
        }
    }
    for entry in recipients {
        if is_eligible(entry, &id.env, id.tier) && !wraps.iter().any(|(rid, _)| *rid == entry.id) {
            return Err(CoreError::HeaderParse {
                reason: format!(
                    "cell {}:{} is missing the wrap for enrolled recipient {}",
                    id.env.as_str(),
                    id.tier.as_u8(),
                    entry.id.as_str()
                ),
            });
        }
    }
    Ok(())
}

/// Weakest wrapped recipient class = the cell's REAL security floor (G-A).
/// Recovery is the deliberate offline exemption, so it is the floor only
/// when nothing else is wrapped.
fn wrap_floor(wraps: &[(RecipientId, Vec<u8>)], recipients: &[RecipientEntry]) -> RecipientClass {
    let mut has_software = false;
    let mut has_hardware = false;
    for (rid, _) in wraps {
        match recipients.iter().find(|e| e.id == *rid).map(|e| e.class) {
            Some(RecipientClass::Software) => has_software = true,
            Some(RecipientClass::Hardware) => has_hardware = true,
            _ => {}
        }
    }
    if has_software {
        RecipientClass::Software
    } else if has_hardware {
        RecipientClass::Hardware
    } else {
        RecipientClass::Recovery
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Transient `Zeroizing` staging copy of a locked DEK for the age boundary
/// (plan/03 window 3; wrap.rs pins the type).
pub(crate) fn stage_dek(dek: &SecretBytes) -> DekBytes {
    let mut staged: DekBytes = Zeroizing::new([0u8; DEK_LEN]);
    dek.with_exposed(|d| staged.copy_from_slice(d));
    staged
}

fn now_epoch() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Random RFC-4122-shaped v4 UUID from `getrandom` (c19; no `rand`).
fn random_uuid() -> Result<VaultUuid, CoreError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(VaultUuid(bytes))
}

fn lock_path_for(vault: &Path) -> PathBuf {
    let name = vault
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_owned());
    vault.with_file_name(format!("{name}.lock"))
}

/// Sidecar advisory flock for the open-modify-save window (plan/02 §8).
/// Non-blocking: a held lock surfaces immediately ("serialize vault edits"
/// is the P0 guidance; the P4 merge driver resolves record-level conflicts).
fn acquire_lock(vault: &Path) -> Result<File, CoreError> {
    let lock_path = lock_path_for(vault);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(FILE_MODE_SECRET)
        .open(&lock_path)?;
    file.try_lock().map_err(|error| {
        CoreError::Io(match error {
            std::fs::TryLockError::WouldBlock => std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "vault {} is locked by another envholster process; serialize vault edits",
                    vault.display()
                ),
            ),
            std::fs::TryLockError::Error(io) => io,
        })
    })?;
    Ok(file)
}

/// One half of the two-phase durable replace (ENVELOPE-SPEC §8.1, Appendix
/// A.11): `stage` writes and fsyncs a temp file (0600) in the target's
/// directory; `commit` atomically renames it over the target and fsyncs the
/// directory. Dropping an uncommitted stage removes the temp file — no
/// partial file is ever left at or beside a target.
struct StagedWrite {
    tmp: PathBuf,
    target: PathBuf,
    dir: PathBuf,
    committed: bool,
}

impl StagedWrite {
    fn stage(path: &Path, bytes: &[u8]) -> std::io::Result<Self> {
        let dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
            _ => PathBuf::from("."),
        };
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault".to_owned());
        let tmp = dir.join(format!(".{file_name}.tmp{}", std::process::id()));

        // A stale temp from a crashed prior run (same pid namespace) is
        // replaced; concurrent writers are excluded by the flock.
        let _ = std::fs::remove_file(&tmp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE_SECRET)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(StagedWrite {
            tmp,
            target: path.to_owned(),
            dir,
            committed: false,
        })
    }

    fn commit(mut self) -> std::io::Result<()> {
        std::fs::rename(&self.tmp, &self.target)?;
        self.committed = true;
        sync_dir(&self.dir)
    }
}

impl Drop for StagedWrite {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    let handle = File::open(dir)?;
    match handle.sync_all() {
        Ok(()) => Ok(()),
        // Some platforms/filesystems refuse fsync on a directory handle
        // (e.g. macOS F_FULLFSYNC on certain vnodes). The rename itself is
        // atomic; degrade to best-effort rather than failing the save.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

// ---------------------------------------------------------------------------
// Tests (std only — no dev-dependencies)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Guarantee, SecretMode};
    use crate::types::Enrollment;
    use secrecy::ExposeSecret;
    use std::collections::HashSet;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "envholster-core-vault-{}-{}-{}",
            std::process::id(),
            tag,
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn all(max_tier: Tier) -> Enrollment {
        Enrollment(EnvSelector::All { max_tier })
    }

    /// One test identity: the age secret key string (re-parsed per use — the
    /// `Identity` enum takes ownership) plus its recipient entry.
    struct TestKey {
        secret: String,
        entry: RecipientEntry,
    }

    impl TestKey {
        fn new(class: RecipientClass, label: &str, enrollment: Enrollment) -> Self {
            let identity = age::x25519::Identity::generate();
            let entry = RecipientEntry::from_encoded(
                &identity.to_public().to_string(),
                class,
                label.to_owned(),
                enrollment,
            )
            .unwrap();
            TestKey {
                secret: identity.to_string().expose_secret().to_owned(),
                entry,
            }
        }

        fn identity(&self) -> Identity {
            Identity::X25519(self.secret.parse().unwrap())
        }
    }

    fn recovery_key() -> TestKey {
        TestKey::new(RecipientClass::Recovery, "paper key", all(Tier::Critical))
    }

    fn software_key() -> TestKey {
        TestKey::new(RecipientClass::Software, "laptop", all(Tier::Ambient))
    }

    fn cell(env: &str, tier: Tier) -> CellId {
        CellId {
            env: EnvName::parse(env).unwrap(),
            tier,
        }
    }

    fn record(value: &[u8]) -> SecretRecord {
        SecretRecord {
            value: SecretBytes::try_from_slice(value).unwrap(),
            mode: SecretMode::ApiKey,
            guarantee: Guarantee::Unassigned,
            created_at: 100,
            updated_at: 100,
            rotated_at: 100,
            rotate_after: None,
            needs_rotation: false,
            metadata: BTreeMap::new(),
        }
    }

    /// Fresh vault with recovery + software recipients; returns
    /// (dir, vault_path, recovery, software, vault).
    fn setup(tag: &str) -> (PathBuf, PathBuf, TestKey, TestKey, Vault) {
        let dir = temp_dir(tag);
        let path = dir.join("secrets.holster");
        let recovery = recovery_key();
        let software = software_key();
        let vault = Vault::create(
            &path,
            vec![recovery.entry.clone(), software.entry.clone()],
            &WrapContext::silent(),
        )
        .unwrap();
        (dir, path, recovery, software, vault)
    }

    #[test]
    fn create_open_add_save_get_round_trip() {
        let (_dir, path, _recovery, software, mut vault) = setup("roundtrip");
        assert_eq!(vault.generation(), 1);
        let uuid = vault.uuid();
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);

        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault
            .add_secret(&base1, "API_KEY", record(b"hunter2"))
            .unwrap();
        vault.save().unwrap();
        assert_eq!(vault.generation(), 2);
        drop(vault); // release the flock before reopening

        let mut reopened = Vault::open(&path).unwrap();
        assert_eq!(reopened.generation(), 2);
        assert_eq!(reopened.uuid(), uuid);
        assert_eq!(reopened.path(), path.as_path());
        assert_eq!(reopened.recipients().len(), 2);

        let statuses = reopened.cells();
        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].unlocked);
        assert_eq!(statuses[0].floor, RecipientClass::Software);

        reopened
            .unlock_cell(&base1, &[software.identity()], &ctx)
            .unwrap();
        let secret = reopened.get_secret(&base1, "API_KEY").unwrap();
        secret.value.with_exposed(|v| assert_eq!(v, b"hunter2"));
        assert_eq!(secret.mode, SecretMode::ApiKey);

        let listed = reopened.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "API_KEY");
        assert_eq!(listed[0].tier, Tier::Ambient);

        // Vault file permissions are 0600 (plan/02 §8).
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "vault file must be 0600");
    }

    #[test]
    fn create_requires_exactly_one_recovery_recipient() {
        let dir = temp_dir("recovery-count");
        let ctx = WrapContext::silent();
        // Zero recovery recipients.
        assert!(matches!(
            Vault::create(&dir.join("zero.holster"), vec![software_key().entry], &ctx),
            Err(CoreError::RecoveryRecipientCount { found: 0 })
        ));
        // Two recovery recipients.
        assert!(matches!(
            Vault::create(
                &dir.join("two.holster"),
                vec![recovery_key().entry, recovery_key().entry],
                &ctx
            ),
            Err(CoreError::RecoveryRecipientCount { found: 2 })
        ));
    }

    #[test]
    fn recovery_enrollment_must_be_all_critical() {
        let dir = temp_dir("recovery-enroll");
        let narrow = TestKey::new(RecipientClass::Recovery, "narrow", all(Tier::Ambient));
        assert!(matches!(
            Vault::create(
                &dir.join("v.holster"),
                vec![narrow.entry],
                &WrapContext::silent()
            ),
            Err(CoreError::InvalidName { .. })
        ));
    }

    #[test]
    fn software_enrollment_above_tier1_is_forbidden_wrap() {
        // G-A: software/CI enrollment is capped at tier 1 — hard error, no
        // override flag exists.
        let dir = temp_dir("ga-enroll");
        let ctx = WrapContext::silent();
        let bad = TestKey::new(RecipientClass::Software, "bad", all(Tier::Sensitive));
        assert!(matches!(
            Vault::create(
                &dir.join("v.holster"),
                vec![recovery_key().entry, bad.entry],
                &ctx
            ),
            Err(CoreError::ForbiddenWrap {
                class: RecipientClass::Software,
                tier: 2,
                ..
            })
        ));

        // Same rule through add_recipient, with a Named enrollment.
        let (_dir, _path, _recovery, _software, mut vault) = setup("ga-add");
        let mut named = BTreeMap::new();
        named.insert(EnvName::parse("prod").unwrap(), Tier::Sensitive);
        let bad = TestKey::new(
            RecipientClass::Software,
            "ci-overreach",
            Enrollment(EnvSelector::Named(named)),
        );
        assert!(matches!(
            vault.add_recipient(bad.entry, &[], &ctx),
            Err(CoreError::ForbiddenWrap {
                class: RecipientClass::Software,
                tier: 2,
                ..
            })
        ));
    }

    #[test]
    fn software_identity_cannot_unwrap_a_tier2_cell() {
        // The wrap-matrix consequence, proven cryptographically: a tier-2
        // cell is never wrapped to a software recipient, so the software
        // identity exhausts the unwrap loop.
        let (_dir, path, recovery, software, mut vault) = setup("tier2");
        let ctx = WrapContext::silent();
        let prod2 = cell("prod", Tier::Sensitive);

        vault.unlock_cell(&prod2, &[], &ctx).unwrap();
        vault
            .add_secret(&prod2, "DB_PASSWORD", record(b"s3cret"))
            .unwrap();
        vault.save().unwrap();

        // The tier-2 cell's floor is Recovery (only wrap present).
        let status = vault.cells().into_iter().find(|s| s.id == prod2).unwrap();
        assert_eq!(status.floor, RecipientClass::Recovery);
        drop(vault);

        let mut reopened = Vault::open(&path).unwrap();
        assert!(matches!(
            reopened.unlock_cell(&prod2, &[software.identity()], &ctx),
            Err(CoreError::NoMatchingIdentity { env, tier: 2, .. }) if env == "prod"
        ));
        // The recovery identity CAN unwrap it (recovery reaches every cell).
        reopened
            .unlock_cell(&prod2, &[recovery.identity()], &ctx)
            .unwrap();
        reopened
            .get_secret(&prod2, "DB_PASSWORD")
            .unwrap()
            .value
            .with_exposed(|v| assert_eq!(v, b"s3cret"));
    }

    #[test]
    fn consecutive_saves_differ_in_nonce_and_ciphertext() {
        let (_dir, path, _recovery, _software, mut vault) = setup("nonce2");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();

        vault.save().unwrap();
        let first = Envelope::parse(&std::fs::read(&path).unwrap()).unwrap();
        vault.save().unwrap(); // identical content
        let second = Envelope::parse(&std::fs::read(&path).unwrap()).unwrap();

        assert_eq!(second.core.generation, first.core.generation + 1);
        assert_ne!(first.core.cells[0].nonce, second.core.cells[0].nonce);
        assert_ne!(first.payloads[0].body, second.payloads[0].body);
        assert_ne!(first.payloads[0].tag, second.payloads[0].tag);
        // Same DEK, same plaintext — only nonce/AAD moved.
        assert_eq!(
            first.core.cells[0].commitment,
            second.core.cells[0].commitment
        );
    }

    #[test]
    fn nonce_uniqueness_over_50_saves() {
        let (_dir, _path, _recovery, _software, mut vault) = setup("nonce50");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();

        let mut nonces: HashSet<[u8; NONCE_LEN]> = HashSet::new();
        let mut bodies: HashSet<Vec<u8>> = HashSet::new();
        for _ in 0..50 {
            vault.save().unwrap();
            assert!(
                nonces.insert(vault.envelope.core.cells[0].nonce),
                "nonce repeated across saves"
            );
            assert!(
                bodies.insert(vault.envelope.payloads[0].body.clone()),
                "ciphertext repeated across saves"
            );
        }
        assert_eq!(nonces.len(), 50);
    }

    #[test]
    fn atomic_save_leaves_no_partial_file_on_failure() {
        let (dir, path, _recovery, _software, mut vault) = setup("atomic");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v1")).unwrap();
        vault.save().unwrap();

        let before_bytes = std::fs::read(&path).unwrap();
        let before_generation = vault.generation();
        let before_names: BTreeSet<String> = dir_entries(&dir);

        // Simulated failure: the directory refuses new files, so the temp
        // file cannot even be created.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        vault
            .edit_secret(&base1, "K", SecretBytes::try_from_slice(b"v2").unwrap())
            .unwrap();
        let result = vault.save();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(result, Err(CoreError::Io(_))));
        // No partial or temp file appeared; the vault bytes are untouched;
        // the in-memory generation did not advance.
        assert_eq!(dir_entries(&dir), before_names);
        assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
        assert_eq!(vault.generation(), before_generation);

        // And the vault is still fully usable afterwards.
        vault.save().unwrap();
        assert_eq!(vault.generation(), before_generation + 1);
    }

    fn dir_entries(dir: &Path) -> BTreeSet<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn save_writes_recovery_blob_in_lockstep() {
        let (_dir, path, recovery, software, mut vault) = setup("lockstep");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"hunter2")).unwrap();
        vault.save().unwrap();

        // The sibling blob exists, 0600, and is a true armored age file.
        let blob_path = crate::recovery::recovery_path_for(&path);
        let armored = std::fs::read(&blob_path).unwrap();
        let mode = std::fs::metadata(&blob_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "recovery blob must be 0600");
        assert!(armored.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----\n"));

        // The recovery identity decrypts it; the software identity does NOT
        // (recovery recipient ONLY — RECOVERY-SPEC §2).
        let json = crate::recovery::decrypt_blob(&armored, &recovery.identity()).unwrap();
        let (generation, uuid) = json
            .with_exposed(crate::recovery::scan_generation_and_uuid)
            .unwrap();
        assert_eq!(generation, vault.generation());
        assert_eq!(uuid, crate::envelope::uuid_to_string(&vault.uuid()));
        json.with_exposed(|j| {
            let text = std::str::from_utf8(j).unwrap();
            assert!(text.contains("\"K\":{"));
            // Value present as base64 ("hunter2" = aHVudGVyMg==).
            assert!(text.contains("\"value\":\"aHVudGVyMg==\""));
        });
        assert!(crate::recovery::decrypt_blob(&armored, &software.identity()).is_err());

        // recovery_test proves the full path (per-cell unwrap + commitment +
        // blob generation match).
        vault.recovery_test(&[recovery.identity()], &ctx).unwrap();
        // …and fails with only the software identity (cannot unwrap blob).
        assert!(vault.recovery_test(&[software.identity()], &ctx).is_err());
    }

    #[test]
    fn recovery_authenticates_persisted_bodies_despite_cached_unlocks() {
        let (_dir, _path, recovery, _software, mut vault) = setup("recovery-cached");
        let ctx = WrapContext::silent();
        let base = cell("base", Tier::Ambient);
        vault.unlock_cell(&base, &[], &ctx).unwrap();
        vault
            .add_secret(&base, "KEY", record(b"synthetic-only"))
            .unwrap();
        vault.save().unwrap();
        assert!(vault.recovery_test(&[recovery.identity()], &ctx).is_ok());
        // Unsaved edits must not change the snapshot being verified.
        vault
            .edit_secret(
                &base,
                "KEY",
                SecretBytes::try_from_slice(b"pending-only").unwrap(),
            )
            .unwrap();
        assert!(vault.recovery_test(&[recovery.identity()], &ctx).is_ok());
        vault.envelope.payloads[0].tag[0] ^= 1;
        assert!(vault.recovery_test(&[recovery.identity()], &ctx).is_err());
    }

    #[test]
    fn recovery_requires_exactly_one_persisted_recovery_recipient() {
        let (_dir, _path, recovery, _software, mut vault) = setup("recovery-recipient-count");
        let ctx = WrapContext::silent();
        // Empty stores still require the correct recovery identity.
        assert!(vault.recovery_test(&[recovery.identity()], &ctx).is_ok());
        vault.envelope.core.recipients.push(recovery.entry.clone());
        assert!(vault.recovery_test(&[recovery.identity()], &ctx).is_err());
        vault
            .envelope
            .core
            .recipients
            .retain(|r| r.class != RecipientClass::Recovery);
        assert!(vault.recovery_test(&[recovery.identity()], &ctx).is_err());
    }

    #[test]
    fn save_fails_closed_when_recovery_blob_is_unwritable() {
        // D6: save fails closed as RecoveryLockstep when the blob cannot be
        // written. A directory squatting on the blob path defeats the rename.
        let (_dir, path, _recovery, _software, mut vault) = setup("lockstep-fail");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();

        let blob_path = crate::recovery::recovery_path_for(&path);
        std::fs::remove_file(&blob_path).unwrap(); // from create()'s save
        std::fs::create_dir(&blob_path).unwrap();
        let generation_before_disk = vault.generation();
        assert!(matches!(
            vault.save(),
            Err(CoreError::RecoveryLockstep { .. })
        ));
        // The failure struck between the renames: the vault advanced, the
        // blob did not — exactly the drift window doctor flags; the next
        // successful save restores lockstep.
        std::fs::remove_dir(&blob_path).unwrap();
        vault.save().unwrap();
        assert!(blob_path.is_file());
        assert!(vault.generation() > generation_before_disk);
    }

    #[test]
    fn recovery_test_detects_generation_drift() {
        let (_dir, path, recovery, _software, mut vault) = setup("drift");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();
        vault.save().unwrap();

        // Hold back the current blob, save again, restore the stale blob.
        let blob_path = crate::recovery::recovery_path_for(&path);
        let stale = std::fs::read(&blob_path).unwrap();
        vault.save().unwrap();
        std::fs::write(&blob_path, &stale).unwrap();
        assert!(matches!(
            vault.recovery_test(&[recovery.identity()], &ctx),
            Err(CoreError::RecoveryLockstep { reason }) if reason.contains("generation drift")
        ));
    }

    #[test]
    fn save_with_a_locked_cell_fails_closed() {
        // Generation is AAD-covered, so save must re-encrypt every persisted
        // cell — a locked cell is CellLocked, never silently carried over.
        let (_dir, path, _recovery, software, mut vault) = setup("locked-save");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        let dev1 = cell("dev", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.unlock_cell(&dev1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "A", record(b"a")).unwrap();
        vault.add_secret(&dev1, "B", record(b"b")).unwrap();
        vault.save().unwrap();
        drop(vault);

        let mut reopened = Vault::open(&path).unwrap();
        reopened
            .unlock_cell(&dev1, &[software.identity()], &ctx)
            .unwrap();
        reopened
            .edit_secret(&dev1, "B", SecretBytes::try_from_slice(b"b2").unwrap())
            .unwrap();
        assert!(matches!(
            reopened.save(),
            Err(CoreError::CellLocked { env, tier: 1 }) if env == "base"
        ));
    }

    #[test]
    fn secret_ops_require_an_unlocked_cell() {
        let (_dir, path, _recovery, _software, mut vault) = setup("cell-locked");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();
        vault.save().unwrap();
        drop(vault);

        let mut reopened = Vault::open(&path).unwrap();
        let locked = |r: Result<(), CoreError>| {
            assert!(matches!(r, Err(CoreError::CellLocked { .. })));
        };
        locked(reopened.add_secret(&base1, "X", record(b"x")));
        assert!(matches!(
            reopened.get_secret(&base1, "K"),
            Err(CoreError::CellLocked { .. })
        ));
        locked(reopened.edit_secret(&base1, "K", SecretBytes::try_from_slice(b"y").unwrap()));
        locked(reopened.remove_secret(&base1, "K"));
        assert!(reopened.list().is_empty());
    }

    #[test]
    fn lock_cell_relocks() {
        let (_dir, _path, _recovery, _software, mut vault) = setup("relock");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();
        vault.save().unwrap();
        vault.lock_cell(&base1);
        assert!(matches!(
            vault.get_secret(&base1, "K"),
            Err(CoreError::CellLocked { .. })
        ));
        assert!(!vault.cells()[0].unlocked);
    }

    #[test]
    fn reserved_metadata_keys_are_refused_at_add() {
        let (_dir, _path, _recovery, _software, mut vault) = setup("reserved-meta");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        let mut bad = record(b"v");
        bad.metadata
            .insert("envholster.anything".to_owned(), "x".to_owned());
        assert!(matches!(
            vault.add_secret(&base1, "K", bad),
            Err(CoreError::InvalidName { name, .. }) if name == "envholster.anything"
        ));
        // Non-reserved metadata is fine.
        let mut good = record(b"v");
        good.metadata.insert("team".to_owned(), "core".to_owned());
        vault.add_secret(&base1, "K", good).unwrap();
    }

    #[test]
    fn duplicate_add_and_missing_names_error() {
        let (_dir, _path, _recovery, _software, mut vault) = setup("dup");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();
        assert!(matches!(
            vault.add_secret(&base1, "K", record(b"w")),
            Err(CoreError::InvalidName { .. })
        ));
        assert!(matches!(
            vault.get_secret(&base1, "MISSING"),
            Err(CoreError::SecretNotFound(name)) if name == "MISSING"
        ));
        assert!(matches!(
            vault.remove_secret(&base1, "MISSING"),
            Err(CoreError::SecretNotFound(_))
        ));
        vault.remove_secret(&base1, "K").unwrap();
        assert!(vault.list().is_empty());
    }

    #[test]
    fn edit_and_rotate_semantics() {
        let (_dir, _path, _recovery, _software, mut vault) = setup("edit-rotate");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        let mut rec = record(b"v1");
        rec.needs_rotation = true;
        vault.add_secret(&base1, "K", rec).unwrap();

        vault
            .edit_secret(&base1, "K", SecretBytes::try_from_slice(b"v2").unwrap())
            .unwrap();
        {
            let secret = vault.get_secret(&base1, "K").unwrap();
            secret.value.with_exposed(|v| assert_eq!(v, b"v2"));
            assert!(secret.updated_at > 100, "edit must bump updated_at");
            assert_eq!(secret.rotated_at, 100);
            assert!(secret.needs_rotation, "edit does not clear the flag");
        }

        vault
            .rotate_secret(&base1, "K", SecretBytes::try_from_slice(b"v3").unwrap())
            .unwrap();
        let secret = vault.get_secret(&base1, "K").unwrap();
        secret.value.with_exposed(|v| assert_eq!(v, b"v3"));
        assert!(secret.rotated_at > 100, "rotate must bump rotated_at");
        assert!(!secret.needs_rotation, "rotate clears needs_rotation");
    }

    #[test]
    fn needs_rotation_survives_save_and_reload_via_reserved_metadata() {
        let (_dir, path, _recovery, software, mut vault) = setup("flag-persist");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        let mut rec = record(b"v");
        rec.needs_rotation = true;
        vault.add_secret(&base1, "K", rec).unwrap();
        vault.save().unwrap();
        drop(vault);

        let mut reopened = Vault::open(&path).unwrap();
        reopened
            .unlock_cell(&base1, &[software.identity()], &ctx)
            .unwrap();
        let secret = reopened.get_secret(&base1, "K").unwrap();
        assert!(secret.needs_rotation);
        // The reserved carrier entry is popped, never user-visible metadata.
        assert!(secret.metadata.is_empty());
    }

    #[test]
    fn remove_recipient_rotates_dek_and_flags_records() {
        let (_dir, path, recovery, software, mut vault) = setup("recipient-rm");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();
        vault.save().unwrap();
        let commitment_before = vault.envelope.core.cells[0].commitment;

        // The affected cell is already unlocked in this session, so no
        // identities are needed for the rotation itself.
        vault
            .remove_recipient(&software.entry.id.clone(), &[], &ctx)
            .unwrap();
        vault.save().unwrap();

        assert_eq!(vault.recipients().len(), 1);
        assert_ne!(
            vault.envelope.core.cells[0].commitment, commitment_before,
            "recipient rm must rotate the cell DEK"
        );
        assert!(vault.get_secret(&base1, "K").unwrap().needs_rotation);
        drop(vault);

        // The removed software identity can no longer unwrap the cell…
        let mut reopened = Vault::open(&path).unwrap();
        assert!(matches!(
            reopened.unlock_cell(&base1, &[software.identity()], &ctx),
            Err(CoreError::NoMatchingIdentity { .. })
        ));
        // …but the remaining recovery recipient can, and the flag persisted.
        reopened
            .unlock_cell(&base1, &[recovery.identity()], &ctx)
            .unwrap();
        assert!(reopened.get_secret(&base1, "K").unwrap().needs_rotation);
    }

    #[test]
    fn removing_the_recovery_recipient_is_refused() {
        let (_dir, _path, recovery, _software, mut vault) = setup("rm-recovery");
        assert!(matches!(
            vault.remove_recipient(&recovery.entry.id.clone(), &[], &WrapContext::silent()),
            Err(CoreError::RecoveryRecipientCount { found: 0 })
        ));
        assert!(matches!(
            vault.remove_recipient(
                &RecipientId::parse("00000000deadbeef").unwrap(),
                &[],
                &WrapContext::silent()
            ),
            Err(CoreError::RecipientNotFound(_))
        ));
    }

    #[test]
    fn add_recipient_wraps_existing_cells() {
        let dir = temp_dir("recipient-add");
        let path = dir.join("secrets.holster");
        let recovery = recovery_key();
        let ctx = WrapContext::silent();
        let mut vault = Vault::create(&path, vec![recovery.entry.clone()], &ctx).unwrap();
        let base1 = cell("base", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();
        vault.save().unwrap();
        assert_eq!(
            vault.cells()[0].floor,
            RecipientClass::Recovery,
            "recovery-only cell before enrollment"
        );

        let newcomer = software_key();
        vault
            .add_recipient(newcomer.entry.clone(), &[], &ctx)
            .unwrap();
        vault.save().unwrap();
        assert_eq!(vault.recipients().len(), 2);
        assert_eq!(vault.cells()[0].floor, RecipientClass::Software);
        // Duplicate enrollment is refused.
        assert!(matches!(
            vault.add_recipient(newcomer.entry.clone(), &[], &ctx),
            Err(CoreError::InvalidName { .. })
        ));
        drop(vault);

        // The new software identity can now unwrap the tier-1 cell.
        let mut reopened = Vault::open(&path).unwrap();
        reopened
            .unlock_cell(&base1, &[newcomer.identity()], &ctx)
            .unwrap();
        reopened
            .get_secret(&base1, "K")
            .unwrap()
            .value
            .with_exposed(|v| assert_eq!(v, b"v"));
    }

    #[test]
    fn flock_excludes_a_second_opener() {
        let (_dir, path, _recovery, _software, vault) = setup("flock");
        // Same-process second open contends on the sidecar flock.
        assert!(matches!(Vault::open(&path), Err(CoreError::Io(_))));
        drop(vault);
        // Released on drop.
        Vault::open(&path).unwrap();
    }

    #[test]
    fn empty_cells_are_not_persisted() {
        let (_dir, path, _recovery, _software, mut vault) = setup("lazy-empty");
        let ctx = WrapContext::silent();
        let base1 = cell("base", Tier::Ambient);
        let dev1 = cell("dev", Tier::Ambient);
        vault.unlock_cell(&base1, &[], &ctx).unwrap();
        vault.unlock_cell(&dev1, &[], &ctx).unwrap();
        vault.add_secret(&base1, "K", record(b"v")).unwrap();
        vault.save().unwrap();
        drop(vault);

        let reopened = Vault::open(&path).unwrap();
        let statuses = reopened.cells();
        assert_eq!(statuses.len(), 1, "record-less dev cell must not persist");
        assert_eq!(statuses[0].id, base1);
    }
}
