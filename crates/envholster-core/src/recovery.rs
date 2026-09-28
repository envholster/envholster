//! Recovery blob — `secrets.holster.recovery.age` (D6; plan/02-envelope §7;
//! RECOVERY-SPEC, frozen).
//!
//! A true armored age file to the single Recovery recipient ONLY, decryptable
//! by vanilla `age -d` with zero envholster code. Its plaintext is the
//! canonical JSON of the FULL store: UTF-8; object keys sorted
//! lexicographically by raw bytes; no insignificant whitespace; no trailing
//! newline; integers plain decimal; strings minimally escaped; values
//! standard padded base64; mode/guarantee as kebab-case names.
//!
//! Memory (plan/03 window 5): the JSON is assembled inside a locked buffer
//! (pre-sized to the exact encoded length — no growth reallocation) and
//! streamed into the age `Encryptor`; never a plain `String`/`Vec` of the
//! whole store. No serde touches this path (c6/c20) — the writer below is a
//! hand-written canonical encoder like HB1 and the header.
//!
//! Lockstep (c3b): the vault's `save` writes the blob on every save and fails
//! closed as `RecoveryLockstep` — the wiring lives in vault.rs; this module
//! owns the bytes.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use envholster_mem::SecretBytes;

use crate::error::CoreError;
use crate::hb1;
use crate::record::SecretRecord;
use crate::types::{EnvName, Identity, RecipientClass, RecipientEntry, Tier};
use crate::ui::WrapContext;
use crate::vault::Vault;

/// The recovery blob lives beside the vault: `<vault-file-name>.recovery.age`
/// (for the canonical `secrets.holster` this is `constants::RECOVERY_FILENAME`).
pub(crate) fn recovery_path_for(vault: &Path) -> PathBuf {
    let name = vault
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_owned());
    vault.with_file_name(format!("{name}.recovery.age"))
}

const _: () = {
    // `secrets.holster` + `.recovery.age` must equal the frozen constant.
    // (Compile-time length check; the string equality is unit-tested below.)
    assert!(
        crate::constants::VAULT_FILENAME.len() + ".recovery.age".len()
            == crate::constants::RECOVERY_FILENAME.len()
    );
};

// ---------------------------------------------------------------------------
// Canonical JSON (RECOVERY-SPEC §3) — hand-written, two-pass (count, write)
// ---------------------------------------------------------------------------

/// One cell's slot in the snapshot handed to the emitter: cells sorted by
/// (env asc, tier asc) — exactly the order the JSON tree needs.
pub(crate) struct SnapshotCell<'a> {
    pub env: &'a EnvName,
    pub tier: Tier,
    pub records: &'a std::collections::BTreeMap<String, SecretRecord>,
}

/// Emits one JSON string literal (quotes included), minimally escaped per
/// RECOVERY-SPEC §3: `"` → `\"`, `\` → `\\`, U+0000–U+001F as the short forms
/// where they exist, otherwise `\u00xx` lowercase hex; everything else
/// emitted literally as UTF-8.
fn emit_string(sink: &mut dyn FnMut(&[u8]), s: &str) {
    sink(b"\"");
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let escape: Option<&[u8]> = match b {
            b'"' => Some(b"\\\""),
            b'\\' => Some(b"\\\\"),
            0x08 => Some(b"\\b"),
            0x09 => Some(b"\\t"),
            0x0a => Some(b"\\n"),
            0x0c => Some(b"\\f"),
            0x0d => Some(b"\\r"),
            0x00..=0x1f => None, // \u00xx below
            _ => continue,
        };
        sink(&bytes[start..i]);
        match escape {
            Some(esc) => sink(esc),
            None => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let buf = [
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(b >> 4) as usize],
                    HEX[(b & 0x0f) as usize],
                ];
                sink(&buf);
            }
        }
        start = i + 1;
    }
    sink(&bytes[start..]);
    sink(b"\"");
}

/// Emits a decimal integer, full 64-bit range, no exponent/leading zeros,
/// `-` only for negatives (RECOVERY-SPEC §3).
fn emit_i64(sink: &mut dyn FnMut(&[u8]), v: i64) {
    emit_dec(sink, v.unsigned_abs(), v < 0);
}

fn emit_u64(sink: &mut dyn FnMut(&[u8]), v: u64) {
    emit_dec(sink, v, false);
}

/// Shared decimal writer (digits assembled in a fixed stack buffer).
fn emit_dec(sink: &mut dyn FnMut(&[u8]), v: u64, negative: bool) {
    let mut buf = [0u8; 21];
    let mut pos = buf.len();
    let mut v = v;
    loop {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if negative {
        pos -= 1;
        buf[pos] = b'-';
    }
    sink(&buf[pos..]);
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 of a secret value, emitted quad-by-quad through the sink — the
/// encoded form of a secret is itself secret, so it must never pass through
/// an ordinary heap `String` (plan/03 window 5); the only transient copies
/// are 4-byte stack quads.
fn emit_b64_value(sink: &mut dyn FnMut(&[u8]), value: &SecretBytes) {
    sink(b"\"");
    value.with_exposed(|v| {
        for chunk in v.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let quad = [
                B64[(b0 >> 2) as usize],
                B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize],
                if chunk.len() > 1 {
                    B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]
                } else {
                    b'='
                },
                if chunk.len() > 2 {
                    B64[(b2 & 0x3f) as usize]
                } else {
                    b'='
                },
            ];
            sink(&quad);
        }
    });
    sink(b"\"");
}

/// Emits the full canonical store JSON (RECOVERY-SPEC §3). `cells` MUST be
/// sorted by (env asc, tier asc) — the vault's persisted cell order.
///
/// Top-level keys in sorted order: envs, generation, saved_at, schema,
/// vault_uuid. Record keys in sorted order: created_at, guarantee, metadata,
/// mode, rotate_after (present only if set), rotated_at, updated_at, value.
pub(crate) fn emit_store_json(
    sink: &mut dyn FnMut(&[u8]),
    cells: &[SnapshotCell<'_>],
    generation: u64,
    saved_at: i64,
    vault_uuid_text: &str,
) {
    sink(b"{\"envs\":{");
    let mut i = 0;
    while i < cells.len() {
        let env = cells[i].env;
        if i > 0 {
            sink(b",");
        }
        emit_string(sink, env.as_str());
        sink(b":{");
        let mut first_tier = true;
        while i < cells.len() && cells[i].env == env {
            let cell = &cells[i];
            if !first_tier {
                sink(b",");
            }
            first_tier = false;
            // Tier keys are the strings "1"/"2"/"3" (JSON keys are strings).
            let tier_key = [b'"', b'0' + cell.tier.as_u8(), b'"'];
            sink(&tier_key);
            sink(b":{");
            let mut first_record = true;
            for (name, record) in cell.records {
                if !first_record {
                    sink(b",");
                }
                first_record = false;
                emit_string(sink, name);
                sink(b":");
                emit_record(sink, record);
            }
            sink(b"}");
            i += 1;
        }
        sink(b"}");
    }
    sink(b"},\"generation\":");
    emit_u64(sink, generation);
    sink(b",\"saved_at\":");
    emit_i64(sink, saved_at);
    sink(b",\"schema\":");
    emit_u64(sink, u64::from(crate::constants::SCHEMA));
    sink(b",\"vault_uuid\":");
    emit_string(sink, vault_uuid_text);
    sink(b"}");
}

fn emit_record(sink: &mut dyn FnMut(&[u8]), record: &SecretRecord) {
    sink(b"{\"created_at\":");
    emit_i64(sink, record.created_at);
    sink(b",\"guarantee\":");
    emit_string(sink, record.guarantee.kebab_name());
    sink(b",\"metadata\":{");
    // Mirrors HB1 metadata verbatim, INCLUDING the reserved needs-rotation
    // entry when set (RECOVERY-SPEC §3).
    let mut first = true;
    for (key, value) in hb1::metadata_entries(record) {
        if !first {
            sink(b",");
        }
        first = false;
        emit_string(sink, key);
        sink(b":");
        emit_string(sink, value);
    }
    sink(b"},\"mode\":");
    emit_string(sink, record.mode.kebab_name());
    if let Some(rotate_after) = record.rotate_after {
        sink(b",\"rotate_after\":");
        emit_i64(sink, rotate_after);
    }
    sink(b",\"rotated_at\":");
    emit_i64(sink, record.rotated_at);
    sink(b",\"updated_at\":");
    emit_i64(sink, record.updated_at);
    sink(b",\"value\":");
    emit_b64_value(sink, &record.value);
    sink(b"}");
}

/// Assembles the canonical store JSON inside a locked buffer, pre-sized to
/// the exact encoded length via a counting pass — growth reallocation would
/// recreate the leak the locked buffer prevents (plan/03 §3.3). The counting
/// pass runs the SAME emitter against a length-summing sink (secret bytes are
/// borrowed inside `with_exposed`, nothing is copied out of the closure).
pub(crate) fn assemble_store_json(
    cells: &[SnapshotCell<'_>],
    generation: u64,
    saved_at: i64,
    vault_uuid_text: &str,
) -> Result<SecretBytes, CoreError> {
    // Pass 1: count.
    let mut total = 0usize;
    {
        let mut count = |bytes: &[u8]| total += bytes.len();
        emit_store_json(&mut count, cells, generation, saved_at, vault_uuid_text);
    }
    // Pass 2: write into the locked buffer.
    let mut out = SecretBytes::try_with_capacity(total)?;
    out.with_exposed_mut(|buf| {
        let mut pos = 0usize;
        let mut write = |bytes: &[u8]| {
            buf[pos..pos + bytes.len()].copy_from_slice(bytes);
            pos += bytes.len();
        };
        emit_store_json(&mut write, cells, generation, saved_at, vault_uuid_text);
        debug_assert_eq!(pos, buf.len(), "recovery JSON size computation drifted");
    });
    Ok(out)
}

// ---------------------------------------------------------------------------
// Age boundary — armored, recovery recipient ONLY
// ---------------------------------------------------------------------------

/// Encrypts the store JSON to the single Recovery recipient as a true armored
/// age file (RECOVERY-SPEC §2): `age -d` with the paper identity is the whole
/// disaster path. The armored ciphertext is not secret.
pub(crate) fn encrypt_store_json(
    json: &SecretBytes,
    recipients: &[RecipientEntry],
) -> Result<Vec<u8>, CoreError> {
    let recovery = recipients
        .iter()
        .find(|r| r.class == RecipientClass::Recovery)
        .ok_or(CoreError::RecoveryRecipientCount { found: 0 })?;
    let encoded = recovery
        .encoded
        .as_deref()
        .ok_or_else(|| CoreError::HeaderParse {
            reason: "recovery recipient has no stored encoding".to_owned(),
        })?;
    let recipient = encoded
        .parse::<age::x25519::Recipient>()
        .map_err(|reason| CoreError::InvalidName {
            name: encoded.to_owned(),
            reason: reason.to_owned(),
        })?;

    let mut armored_out: Vec<u8> = Vec::new();
    let armor =
        age::armor::ArmoredWriter::wrap_output(&mut armored_out, age::armor::Format::AsciiArmor)?;
    let mut writer =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?
            .wrap_output(armor)?;
    // Streamed from the locked buffer (plan/03 window 5); age's STREAM
    // internals are the documented irreducible residual (window 4).
    json.with_exposed(|j| writer.write_all(j))?;
    writer.finish()?.finish()?;
    Ok(armored_out)
}

/// Decrypts an armored recovery blob into a locked buffer with the supplied
/// identity. Plaintext length is bounded by the armored length (base64
/// expansion + age overhead), so the buffer is pre-sized and truncated —
/// never grown.
pub(crate) fn decrypt_blob(armored: &[u8], identity: &Identity) -> Result<SecretBytes, CoreError> {
    let age_identity: &dyn age::Identity = match identity {
        Identity::X25519(id) => id,
        _ => {
            return Err(CoreError::HeaderParse {
                reason: "the recovery blob decrypts with an x25519 identity".to_owned(),
            })
        }
    };
    let reader = age::armor::ArmoredReader::new(armored);
    let decryptor = age::Decryptor::new_buffered(reader).map_err(CoreError::AgeDecrypt)?;
    let mut stream = decryptor
        .decrypt(std::iter::once(age_identity))
        .map_err(CoreError::AgeDecrypt)?;

    let mut out = SecretBytes::try_with_capacity(armored.len())?;
    let filled = out
        .with_exposed_mut(|buf| -> std::io::Result<usize> {
            let mut filled = 0usize;
            loop {
                let n = stream.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
                if filled == buf.len() {
                    // Cannot happen: plaintext < armored ciphertext. Treat a
                    // full buffer as corruption rather than reallocating.
                    return Err(std::io::Error::other(
                        "recovery blob plaintext exceeds its armored length",
                    ));
                }
            }
            Ok(filled)
        })
        .map_err(CoreError::Io)?;
    out.truncate(filled);
    Ok(out)
}

/// Extracts `generation` and `vault_uuid` from canonical store JSON by
/// scanning for the LAST occurrences of the top-level keys. Sound because the
/// JSON is canonical: an unescaped `"generation":` byte sequence cannot occur
/// inside any string literal (interior quotes are always `\"`), and the
/// top-level keys sort after `envs`, so theirs are the final occurrences.
pub(crate) fn scan_generation_and_uuid(json: &[u8]) -> Option<(u64, String)> {
    let generation_at = find_last(json, b",\"generation\":")?;
    let mut pos = generation_at + b",\"generation\":".len();
    let mut generation: u64 = 0;
    let mut any = false;
    while pos < json.len() && json[pos].is_ascii_digit() {
        generation = generation
            .checked_mul(10)?
            .checked_add(u64::from(json[pos] - b'0'))?;
        pos += 1;
        any = true;
    }
    if !any {
        return None;
    }

    let uuid_at = find_last(json, b",\"vault_uuid\":\"")?;
    let start = uuid_at + b",\"vault_uuid\":\"".len();
    let end = start + 36;
    if end + 2 != json.len() || &json[end..] != b"\"}" {
        return None;
    }
    let uuid = std::str::from_utf8(&json[start..end]).ok()?.to_owned();
    Some((generation, uuid))
}

fn scan_saved_at(json: &[u8]) -> Option<i64> {
    let start = find_last(json, b",\"saved_at\":")? + b",\"saved_at\":".len();
    let rest = json.get(start..)?;
    let end = rest.iter().position(|b| *b == b',')?;
    std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| &haystack[i..i + needle.len()] == needle)
}

// ---------------------------------------------------------------------------
// `recovery test` support (RECOVERY-SPEC §6, c42)
// ---------------------------------------------------------------------------

impl Vault {
    /// Authenticates every persisted cell through its recovery wrap, including
    /// the body tag and record encoding, then compares the complete canonical
    /// backup with those records. Cached unlocks and pending edits are ignored.
    /// Generation and UUID must match. `saved_at` is informational: the primary
    /// has no independent timestamp to compare, so any canonical i64 is allowed.
    pub fn recovery_test(
        &self,
        identities: &[Identity],
        ctx: &WrapContext,
    ) -> Result<(), CoreError> {
        let recipient = self.persisted_recovery_recipient()?;
        let identity = identities
            .iter()
            .find(|identity| match identity {
                Identity::X25519(id) => {
                    recipient.encoded.as_deref() == Some(id.to_public().to_string().as_str())
                }
                _ => false,
            })
            .ok_or_else(|| CoreError::RecoveryLockstep {
                reason: "the selected identity is not this vault's recovery recipient".to_owned(),
            })?;
        let records = self.recovery_records(std::slice::from_ref(identity), ctx)?;
        let blob_path = recovery_path_for(self.path());
        let armored = std::fs::read(&blob_path).map_err(|error| CoreError::RecoveryLockstep {
            reason: format!("recovery blob {} unreadable: {error}", blob_path.display()),
        })?;
        let json = decrypt_blob(&armored, identity)?;
        let (blob_generation, blob_uuid) =
            json.with_exposed(scan_generation_and_uuid).ok_or_else(|| {
                CoreError::RecoveryLockstep {
                    reason: "recovery blob plaintext is not canonical store JSON".to_owned(),
                }
            })?;
        if blob_generation != self.generation() {
            return Err(CoreError::RecoveryLockstep {
                reason: format!(
                    "generation drift: vault {} vs recovery blob {} — re-save to restore lockstep",
                    self.generation(),
                    blob_generation
                ),
            });
        }
        let vault_uuid = crate::envelope::uuid_to_string(&self.uuid());
        if blob_uuid != vault_uuid {
            return Err(CoreError::RecoveryLockstep {
                reason: format!(
                    "vault uuid mismatch: vault {vault_uuid} vs recovery blob {blob_uuid}"
                ),
            });
        }
        let cells: Vec<_> = records
            .iter()
            .map(|(cell, records)| SnapshotCell {
                env: &cell.env,
                tier: cell.tier,
                records,
            })
            .collect();
        let matches = json.with_exposed(|bytes| {
            // saved_at has no independent copy in the primary vault. Treat it
            // as informational, while canonical comparison verifies all data.
            let Some(saved_at) = scan_saved_at(bytes) else {
                return false;
            };
            let mut offset = 0usize;
            let mut equal = true;
            emit_store_json(
                &mut |chunk| {
                    let end = offset.saturating_add(chunk.len());
                    equal &= bytes.get(offset..end) == Some(chunk);
                    offset = end;
                },
                &cells,
                self.generation(),
                saved_at,
                &vault_uuid,
            );
            equal && offset == bytes.len()
        });
        if !matches {
            return Err(CoreError::RecoveryLockstep {
                reason: "recovery snapshot contents do not match the authenticated vault"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Guarantee, SecretMode};
    use crate::types::{Enrollment, EnvSelector};
    use std::collections::BTreeMap;

    #[test]
    fn recovery_path_matches_frozen_constant() {
        assert_eq!(
            recovery_path_for(Path::new(crate::constants::VAULT_FILENAME)),
            Path::new(crate::constants::RECOVERY_FILENAME)
        );
        assert_eq!(
            recovery_path_for(Path::new("/a/b/secrets.holster")),
            Path::new("/a/b/secrets.holster.recovery.age")
        );
    }

    fn collect(f: impl FnOnce(&mut dyn FnMut(&[u8]))) -> Vec<u8> {
        let mut out = Vec::new();
        let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
        f(&mut sink);
        out
    }

    #[test]
    fn string_escaping_is_minimal_and_exact() {
        let cases: &[(&str, &str)] = &[
            ("plain", "\"plain\""),
            ("with \"quotes\"", "\"with \\\"quotes\\\"\""),
            ("back\\slash", "\"back\\\\slash\""),
            (
                "tab\tnl\ncr\rbs\x08ff\x0c",
                "\"tab\\tnl\\ncr\\rbs\\bff\\f\"",
            ),
            ("nul\x00esc\x1b", "\"nul\\u0000esc\\u001b\""),
            ("unicode é 日本", "\"unicode é 日本\""),
        ];
        for (input, expected) in cases {
            let out = collect(|sink| emit_string(sink, input));
            assert_eq!(std::str::from_utf8(&out).unwrap(), *expected);
        }
    }

    #[test]
    fn integers_are_plain_decimal_full_range() {
        for (v, expected) in [
            (0i64, "0"),
            (-1, "-1"),
            (i64::MAX, "9223372036854775807"),
            (i64::MIN, "-9223372036854775808"),
        ] {
            let out = collect(|sink| emit_i64(sink, v));
            assert_eq!(std::str::from_utf8(&out).unwrap(), expected);
        }
        let out = collect(|sink| emit_u64(sink, u64::MAX));
        assert_eq!(std::str::from_utf8(&out).unwrap(), "18446744073709551615");
    }

    fn record(value: &[u8], mode: SecretMode) -> SecretRecord {
        SecretRecord {
            value: SecretBytes::try_from_slice(value).unwrap(),
            mode,
            guarantee: Guarantee::Unassigned,
            created_at: 1767225600,
            updated_at: 1767225600,
            rotated_at: 1767225600,
            rotate_after: None,
            needs_rotation: false,
            metadata: BTreeMap::new(),
        }
    }

    /// The RECOVERY-SPEC §3.1 example, byte for byte — the strongest pin on
    /// the canonical JSON writer (it is also the vault-basic expected.json).
    #[test]
    fn spec_example_store_renders_byte_exact() {
        let base_env = EnvName::parse("base").unwrap();
        let prod_env = EnvName::parse("prod").unwrap();

        let mut base_records = BTreeMap::new();
        base_records.insert(
            "ALPHA".to_owned(),
            record(b"golden-alpha-value", SecretMode::EnvVar),
        );

        let mut prod_records = BTreeMap::new();
        let mut api_key = record(b"golden-api-key-value", SecretMode::ApiKey);
        api_key.rotate_after = Some(7776000);
        api_key
            .metadata
            .insert("provider".to_owned(), "example".to_owned());
        prod_records.insert("API_KEY".to_owned(), api_key);
        let mut db_password = record(b"golden-db-password", SecretMode::ApiKey);
        db_password.needs_rotation = true;
        prod_records.insert("DB_PASSWORD".to_owned(), db_password);

        let cells = [
            SnapshotCell {
                env: &base_env,
                tier: Tier::Ambient,
                records: &base_records,
            },
            SnapshotCell {
                env: &prod_env,
                tier: Tier::Ambient,
                records: &prod_records,
            },
        ];
        let json = assemble_store_json(
            &cells,
            3,
            1767225600,
            "3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55",
        )
        .unwrap();

        let expected = concat!(
            "{\"envs\":{\"base\":{\"1\":{\"ALPHA\":{\"created_at\":1767225600,",
            "\"guarantee\":\"unassigned\",\"metadata\":{},\"mode\":\"env-var\",",
            "\"rotated_at\":1767225600,\"updated_at\":1767225600,",
            "\"value\":\"Z29sZGVuLWFscGhhLXZhbHVl\"}}},\"prod\":{\"1\":{",
            "\"API_KEY\":{\"created_at\":1767225600,\"guarantee\":\"unassigned\",",
            "\"metadata\":{\"provider\":\"example\"},\"mode\":\"api-key\",",
            "\"rotate_after\":7776000,\"rotated_at\":1767225600,",
            "\"updated_at\":1767225600,\"value\":\"Z29sZGVuLWFwaS1rZXktdmFsdWU=\"},",
            "\"DB_PASSWORD\":{\"created_at\":1767225600,\"guarantee\":\"unassigned\",",
            "\"metadata\":{\"envholster.needs-rotation\":\"1\"},\"mode\":\"api-key\",",
            "\"rotated_at\":1767225600,\"updated_at\":1767225600,",
            "\"value\":\"Z29sZGVuLWRiLXBhc3N3b3Jk\"}}}},\"generation\":3,",
            "\"saved_at\":1767225600,\"schema\":1,",
            "\"vault_uuid\":\"3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55\"}"
        );
        json.with_exposed(|j| {
            assert_eq!(
                std::str::from_utf8(j).unwrap(),
                expected,
                "canonical JSON drifted from the RECOVERY-SPEC §3.1 example"
            )
        });

        // The tail scanner recovers the top-level fields.
        let (generation, uuid) = json.with_exposed(scan_generation_and_uuid).unwrap();
        assert_eq!(generation, 3);
        assert_eq!(uuid, "3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55");
    }

    #[test]
    fn scanner_ignores_decoy_metadata_keys() {
        // A metadata key literally named "generation" appears earlier in the
        // byte stream than the top-level key; the last-occurrence scan must
        // return the top-level value.
        let env = EnvName::parse("base").unwrap();
        let mut rec = record(b"v", SecretMode::Generic);
        rec.metadata
            .insert("generation".to_owned(), "999".to_owned());
        rec.metadata
            .insert("vault_uuid".to_owned(), "fake".to_owned());
        let mut records = BTreeMap::new();
        records.insert("K".to_owned(), rec);
        let cells = [SnapshotCell {
            env: &env,
            tier: Tier::Ambient,
            records: &records,
        }];
        let json =
            assemble_store_json(&cells, 7, 0, "00000000-0000-0000-0000-000000000000").unwrap();
        let (generation, uuid) = json.with_exposed(scan_generation_and_uuid).unwrap();
        assert_eq!(generation, 7);
        assert_eq!(uuid, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn empty_store_renders_and_scans() {
        let json = assemble_store_json(&[], 1, 42, "3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55").unwrap();
        json.with_exposed(|j| {
            assert_eq!(
                std::str::from_utf8(j).unwrap(),
                "{\"envs\":{},\"generation\":1,\"saved_at\":42,\"schema\":1,\
                 \"vault_uuid\":\"3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55\"}"
            )
        });
        let (generation, _) = json.with_exposed(scan_generation_and_uuid).unwrap();
        assert_eq!(generation, 1);
    }

    #[test]
    fn armored_round_trip_to_recovery_recipient_only() {
        let recovery_identity = age::x25519::Identity::generate();
        let stranger = age::x25519::Identity::generate();
        let entry = RecipientEntry::from_encoded(
            &recovery_identity.to_public().to_string(),
            RecipientClass::Recovery,
            "paper".to_owned(),
            Enrollment(EnvSelector::All {
                max_tier: Tier::Critical,
            }),
        )
        .unwrap();

        let json = SecretBytes::try_from_slice(b"{\"envs\":{}}").unwrap();
        let armored = encrypt_store_json(&json, std::slice::from_ref(&entry)).unwrap();
        let text = std::str::from_utf8(&armored).unwrap();
        assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----\n"));
        assert!(text
            .trim_end()
            .ends_with("-----END AGE ENCRYPTED FILE-----"));
        assert!(!text.contains('\r'), "armor must be LF-terminated");

        // The recovery identity decrypts…
        let plain = decrypt_blob(&armored, &Identity::X25519(recovery_identity)).unwrap();
        plain.with_exposed(|p| assert_eq!(p, b"{\"envs\":{}}"));
        // …and nobody else does (recovery recipient ONLY).
        assert!(matches!(
            decrypt_blob(&armored, &Identity::X25519(stranger)),
            Err(CoreError::AgeDecrypt(_))
        ));
    }
}
