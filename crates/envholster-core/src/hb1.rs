//! HB1 — the cell-body codec (plan/02-envelope §5).
//!
//! Hand-rolled canonical length-prefixed binary; all integers little-endian
//! fixed width; written and parsed ONLY inside locked buffers via
//! `SecretBytes::with_exposed`/`with_exposed_mut` (plan/03-memory §3.3,
//! window 1). No serde in any encrypted path (c6/c20). Buffers are pre-sized
//! to the exact encoded length — no growing `Vec`s (plan/03 §3.3).
//!
//! Canonical = exactly one byte sequence per logical content: records sorted
//! by name bytes ascending (duplicates = parse error), metadata entries
//! sorted by key bytes ascending, no trailing bytes after the last record.
//! The record `tier` byte MUST equal the cell's tier (defensive duplication;
//! mismatch = parse error).
//!
//! `needs_rotation` is NOT an HB1 grammar field: it persists as the reserved
//! metadata entry `METADATA_KEY_NEEDS_ROTATION = "1"`, merged into the sorted
//! metadata slots by the encoder and popped back into the struct field by the
//! parser (plan/04-contracts §4.3).

use std::collections::BTreeMap;

use envholster_mem::SecretBytes;

use crate::constants::{METADATA_KEY_NEEDS_ROTATION, METADATA_RESERVED_PREFIX};
use crate::error::CoreError;
use crate::record::{Guarantee, SecretMode, SecretRecord};
use crate::types::Tier;

/// Secret-name length limit in bytes (plan/02-envelope §5).
pub(crate) const SECRET_NAME_MAX: usize = 128;

fn body_err(reason: impl Into<String>) -> CoreError {
    CoreError::HeaderParse {
        reason: format!("cell body (HB1): {}", reason.into()),
    }
}

/// Secret-name charset `[A-Za-z0-9_.-]{1,128}` (plan/02-envelope §5).
pub(crate) fn validate_secret_name(name: &str) -> Result<(), CoreError> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= SECRET_NAME_MAX
        && bytes
            .iter()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(CoreError::InvalidName {
            name: name.to_owned(),
            reason: "secret names must match [A-Za-z0-9_.-]{1,128}".to_owned(),
        })
    }
}

/// One record's metadata entries in canonical HB1 order: the (already
/// key-sorted) map merged with the synthetic reserved needs-rotation entry
/// iff the flag is set. Keys and values are non-secret (plan/04 §4.3).
/// Shared with the recovery blob, which mirrors HB1 metadata verbatim
/// including the reserved entry (RECOVERY-SPEC §3).
pub(crate) fn metadata_entries(record: &SecretRecord) -> Vec<(&str, &str)> {
    let mut entries: Vec<(&str, &str)> = record
        .metadata
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    if record.needs_rotation {
        let pos = entries.partition_point(|(k, _)| *k < METADATA_KEY_NEEDS_ROTATION);
        entries.insert(pos, (METADATA_KEY_NEEDS_ROTATION, "1"));
    }
    entries
}

/// Exact encoded length of one record (drives the pre-sized locked buffer).
fn record_encoded_len(name: &str, record: &SecretRecord) -> usize {
    let meta: usize = metadata_entries(record)
        .iter()
        .map(|(k, v)| 2 + k.len() + 4 + v.len())
        .sum();
    2 + name.len()                                           // name
        + 1 + 1 + 1                                          // tier, mode, guarantee
        + 8 * 3                                              // created/updated/rotated_at
        + 1 + if record.rotate_after.is_some() { 8 } else { 0 }
        + 2 + meta                                           // metadata count + entries
        + 4 + record.value.len() // value
}

/// Bounds-exact cursor over the exposed locked buffer.
struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
}

/// Encodes one cell's records into a freshly allocated, exactly-sized locked
/// buffer — the same buffer the caller then encrypts in place (plan/03 §3.3
/// windows 1–2). `tier` is the owning cell's tier, duplicated defensively
/// into every record.
pub(crate) fn encode(
    records: &BTreeMap<String, SecretRecord>,
    tier: Tier,
) -> Result<SecretBytes, CoreError> {
    let count = u32::try_from(records.len())
        .map_err(|_| body_err("more than u32::MAX records in one cell"))?;

    // Validate + size in one pass before allocating the locked buffer.
    let mut total = 4usize;
    for (name, record) in records {
        validate_secret_name(name)?;
        for key in record.metadata.keys() {
            // Reserved-namespace keys never travel in the map: schema 1
            // defines exactly one (needs-rotation), carried by the struct
            // field, and writers MUST NOT emit any other reserved key
            // (ENVELOPE-SPEC §7.2).
            if key.starts_with(METADATA_RESERVED_PREFIX) {
                return Err(body_err(format!(
                    "reserved metadata key {key:?}: schema 1 writers may only emit \
                     {METADATA_KEY_NEEDS_ROTATION:?}, via the needs_rotation field"
                )));
            }
        }
        for (key, value) in &record.metadata {
            if key.len() > u16::MAX as usize {
                return Err(body_err("metadata key exceeds u16::MAX bytes"));
            }
            if value.len() > u32::MAX as usize {
                return Err(body_err("metadata value exceeds u32::MAX bytes"));
            }
        }
        if metadata_entries(record).len() > u16::MAX as usize {
            return Err(body_err("more than u16::MAX metadata entries"));
        }
        if record.value.len() > u32::MAX as usize {
            return Err(body_err("secret value exceeds u32::MAX bytes"));
        }
        total += record_encoded_len(name, record);
    }

    let mut out = SecretBytes::try_with_capacity(total)?;
    out.with_exposed_mut(|buf| {
        let mut w = Writer { buf, pos: 0 };
        w.put(&count.to_le_bytes());
        for (name, record) in records {
            w.put(&(name.len() as u16).to_le_bytes());
            w.put(name.as_bytes());
            w.put(&[tier.as_u8(), record.mode.as_u8(), record.guarantee.as_u8()]);
            w.put(&record.created_at.to_le_bytes());
            w.put(&record.updated_at.to_le_bytes());
            w.put(&record.rotated_at.to_le_bytes());
            match record.rotate_after {
                Some(seconds) => {
                    w.put(&[1]);
                    w.put(&seconds.to_le_bytes());
                }
                None => w.put(&[0]),
            }
            let meta = metadata_entries(record);
            w.put(&(meta.len() as u16).to_le_bytes());
            for (key, value) in meta {
                w.put(&(key.len() as u16).to_le_bytes());
                w.put(key.as_bytes());
                w.put(&(value.len() as u32).to_le_bytes());
                w.put(value.as_bytes());
            }
            w.put(&(record.value.len() as u32).to_le_bytes());
            record.value.with_exposed(|v| w.put(v));
        }
        debug_assert_eq!(w.pos, w.buf.len(), "HB1 size computation drifted");
    });
    Ok(out)
}

/// Strict cursor over the exposed plaintext.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CoreError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or_else(|| body_err("truncated record data"))?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, CoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoreError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("len 2")))
    }

    fn u32(&mut self) -> Result<u32, CoreError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("len 4")))
    }

    fn i64(&mut self) -> Result<i64, CoreError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().expect("len 8")))
    }
}

fn utf8(bytes: &[u8], what: &str) -> Result<String, CoreError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| body_err(format!("{what} is not UTF-8")))
}

/// Parses one cell's decrypted plaintext, exposing the locked buffer
/// read-only for the duration; secret values are copied straight into fresh
/// locked buffers (`SecretBytes::try_from_slice`), never through the heap.
pub(crate) fn parse(
    body: &SecretBytes,
    tier: Tier,
) -> Result<BTreeMap<String, SecretRecord>, CoreError> {
    body.with_exposed(|buf| parse_exposed(buf, tier))
}

fn parse_exposed(buf: &[u8], tier: Tier) -> Result<BTreeMap<String, SecretRecord>, CoreError> {
    let mut r = Reader { buf, pos: 0 };
    let count = r.u32()?;
    let mut records = BTreeMap::new();
    let mut prev_name: Option<String> = None;
    for _ in 0..count {
        let name_len = r.u16()? as usize;
        let name = utf8(r.take(name_len)?, "record name")?;
        validate_secret_name(&name)
            .map_err(|_| body_err(format!("record name {name:?} violates the name charset")))?;
        if let Some(prev) = &prev_name {
            if prev.as_bytes() >= name.as_bytes() {
                return Err(body_err(
                    "records must be sorted by name bytes ascending, without duplicates",
                ));
            }
        }

        let record_tier = r.u8()?;
        if record_tier != tier.as_u8() {
            return Err(body_err(format!(
                "record {name:?} carries tier {record_tier}, but its cell is tier {}",
                tier.as_u8()
            )));
        }
        let mode = SecretMode::try_from_u8(r.u8()?)
            .ok_or_else(|| body_err(format!("record {name:?} has an unknown mode byte")))?;
        let guarantee = Guarantee::try_from_u8(r.u8()?)
            .ok_or_else(|| body_err(format!("record {name:?} has an unknown guarantee byte")))?;
        let created_at = r.i64()?;
        let updated_at = r.i64()?;
        let rotated_at = r.i64()?;
        let rotate_after = match r.u8()? {
            0 => None,
            1 => Some(r.i64()?),
            _ => return Err(body_err("rotate_after presence flag must be 0 or 1")),
        };

        let meta_count = r.u16()?;
        let mut metadata = BTreeMap::new();
        let mut needs_rotation = false;
        let mut prev_key: Option<String> = None;
        for _ in 0..meta_count {
            let key_len = r.u16()? as usize;
            let key = utf8(r.take(key_len)?, "metadata key")?;
            if let Some(prev) = &prev_key {
                if prev.as_bytes() >= key.as_bytes() {
                    return Err(body_err(
                        "metadata entries must be sorted by key bytes ascending, without duplicates",
                    ));
                }
            }
            let value_len = r.u32()? as usize;
            let value_bytes = r.take(value_len)?;
            if key == METADATA_KEY_NEEDS_ROTATION {
                // Popped into the struct field (plan/04 §4.3).
                if value_bytes != b"1" {
                    return Err(body_err(format!(
                        "{METADATA_KEY_NEEDS_ROTATION:?} must carry the value \"1\""
                    )));
                }
                needs_rotation = true;
            } else if key.starts_with(METADATA_RESERVED_PREFIX) {
                // Unknown reserved keys are parse errors in schema 1 — the
                // reserved namespace is versioned by schema; a new key
                // requires a schema bump (ENVELOPE-SPEC §7.2, Appendix A.10).
                return Err(body_err(format!(
                    "unknown reserved metadata key {key:?} (schema bump required)"
                )));
            } else {
                let value = utf8(value_bytes, "metadata value")?;
                metadata.insert(key.clone(), value);
            }
            prev_key = Some(key);
        }

        let value_len = r.u32()? as usize;
        let value = SecretBytes::try_from_slice(r.take(value_len)?)?;

        records.insert(
            name.clone(),
            SecretRecord {
                value,
                mode,
                guarantee,
                created_at,
                updated_at,
                rotated_at,
                rotate_after,
                needs_rotation,
                metadata,
            },
        );
        prev_name = Some(name);
    }
    if r.pos != buf.len() {
        return Err(body_err("trailing bytes after the last record"));
    }
    Ok(records)
}

// ---------------------------------------------------------------------------
// Tests (std only — no dev-dependencies)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::METADATA_RESERVED_PREFIX;

    fn record(value: &[u8]) -> SecretRecord {
        SecretRecord {
            value: SecretBytes::try_from_slice(value).unwrap(),
            mode: SecretMode::ApiKey,
            guarantee: Guarantee::Unassigned,
            created_at: 100,
            updated_at: 200,
            rotated_at: 300,
            rotate_after: None,
            needs_rotation: false,
            metadata: BTreeMap::new(),
        }
    }

    /// The golden HB1 vector, hand-assembled byte by byte (plan/02 §5).
    /// One record: name "API_KEY", tier 1, mode api-key (3), guarantee
    /// unassigned (0), timestamps 100/200/300, rotate_after 86400, metadata
    /// {"note": "x"} plus the synthetic needs-rotation entry, value "hunter2".
    fn golden_bytes() -> Vec<u8> {
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(&1u32.to_le_bytes()); // record_count
        expected.extend_from_slice(&7u16.to_le_bytes()); // name len
        expected.extend_from_slice(b"API_KEY");
        expected.push(1); // tier
        expected.push(3); // mode = api-key
        expected.push(0); // guarantee = unassigned
        expected.extend_from_slice(&100i64.to_le_bytes()); // created_at
        expected.extend_from_slice(&200i64.to_le_bytes()); // updated_at
        expected.extend_from_slice(&300i64.to_le_bytes()); // rotated_at
        expected.push(1); // rotate_after present
        expected.extend_from_slice(&86400i64.to_le_bytes());
        expected.extend_from_slice(&2u16.to_le_bytes()); // metadata count
        expected.extend_from_slice(&25u16.to_le_bytes()); // "envholster.needs-rotation"
        expected.extend_from_slice(b"envholster.needs-rotation");
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"1");
        expected.extend_from_slice(&4u16.to_le_bytes()); // "note"
        expected.extend_from_slice(b"note");
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"x");
        expected.extend_from_slice(&7u32.to_le_bytes()); // value
        expected.extend_from_slice(b"hunter2");
        expected
    }

    #[test]
    fn golden_round_trip() {
        let mut rec = record(b"hunter2");
        rec.rotate_after = Some(86400);
        rec.needs_rotation = true;
        rec.metadata.insert("note".to_owned(), "x".to_owned());
        let mut records = BTreeMap::new();
        records.insert("API_KEY".to_owned(), rec);

        let body = encode(&records, Tier::Ambient).unwrap();
        let expected = golden_bytes();
        body.with_exposed(|b| {
            assert_eq!(b, &expected[..], "encoder drifted from the golden vector")
        });

        let parsed = parse(
            &SecretBytes::try_from_slice(&expected).unwrap(),
            Tier::Ambient,
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        let rec = &parsed["API_KEY"];
        rec.value.with_exposed(|v| assert_eq!(v, b"hunter2"));
        assert_eq!(rec.mode, SecretMode::ApiKey);
        assert_eq!(rec.guarantee, Guarantee::Unassigned);
        assert_eq!(
            (rec.created_at, rec.updated_at, rec.rotated_at),
            (100, 200, 300)
        );
        assert_eq!(rec.rotate_after, Some(86400));
        // The reserved entry is popped into the field, never left in the map.
        assert!(rec.needs_rotation);
        assert_eq!(rec.metadata.len(), 1);
        assert_eq!(rec.metadata["note"], "x");
    }

    #[test]
    fn empty_cell_round_trips() {
        let records = BTreeMap::new();
        let body = encode(&records, Tier::Critical).unwrap();
        assert_eq!(body.len(), 4);
        body.with_exposed(|b| assert_eq!(b, &0u32.to_le_bytes()));
        assert!(parse(&body, Tier::Critical).unwrap().is_empty());
    }

    #[test]
    fn multi_record_encode_is_name_sorted_and_round_trips() {
        let mut records = BTreeMap::new();
        records.insert("ZED".to_owned(), record(b"z"));
        records.insert("ALPHA".to_owned(), record(b"a"));
        let body = encode(&records, Tier::Sensitive).unwrap();
        // ALPHA must serialize before ZED (BTreeMap order = byte order).
        body.with_exposed(|b| {
            let alpha = b.windows(5).position(|w| w == b"ALPHA").unwrap();
            let zed = b.windows(3).position(|w| w == b"ZED").unwrap();
            assert!(alpha < zed);
        });
        let parsed = parse(&body, Tier::Sensitive).unwrap();
        assert_eq!(parsed.len(), 2);
        parsed["ALPHA"].value.with_exposed(|v| assert_eq!(v, b"a"));
        parsed["ZED"].value.with_exposed(|v| assert_eq!(v, b"z"));
    }

    #[test]
    fn tier_mismatch_is_a_parse_error() {
        let mut records = BTreeMap::new();
        records.insert("A".to_owned(), record(b"v"));
        let body = encode(&records, Tier::Ambient).unwrap();
        assert!(matches!(
            parse(&body, Tier::Sensitive),
            Err(CoreError::HeaderParse { .. })
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = golden_bytes();
        bytes.push(0);
        assert!(matches!(
            parse(&SecretBytes::try_from_slice(&bytes).unwrap(), Tier::Ambient),
            Err(CoreError::HeaderParse { .. })
        ));
    }

    #[test]
    fn truncation_is_rejected() {
        let bytes = golden_bytes();
        for cut in [3, 10, bytes.len() - 1] {
            assert!(
                parse(
                    &SecretBytes::try_from_slice(&bytes[..cut]).unwrap(),
                    Tier::Ambient
                )
                .is_err(),
                "expected error at cut {cut}"
            );
        }
    }

    #[test]
    fn unsorted_or_duplicate_names_are_rejected() {
        // Two records, "B" before "A": violates the mandated sort order.
        let mut rec_a = BTreeMap::new();
        rec_a.insert("A".to_owned(), record(b"a"));
        let mut rec_b = BTreeMap::new();
        rec_b.insert("B".to_owned(), record(b"b"));
        let body_a = encode(&rec_a, Tier::Ambient).unwrap();
        let body_b = encode(&rec_b, Tier::Ambient).unwrap();
        let a_bytes = body_a.with_exposed(|b| b[4..].to_vec());
        let b_bytes = body_b.with_exposed(|b| b[4..].to_vec());

        let mut unsorted = Vec::new();
        unsorted.extend_from_slice(&2u32.to_le_bytes());
        unsorted.extend_from_slice(&b_bytes);
        unsorted.extend_from_slice(&a_bytes);
        assert!(parse(
            &SecretBytes::try_from_slice(&unsorted).unwrap(),
            Tier::Ambient
        )
        .is_err());

        let mut duplicate = Vec::new();
        duplicate.extend_from_slice(&2u32.to_le_bytes());
        duplicate.extend_from_slice(&a_bytes);
        duplicate.extend_from_slice(&a_bytes);
        assert!(parse(
            &SecretBytes::try_from_slice(&duplicate).unwrap(),
            Tier::Ambient
        )
        .is_err());
    }

    #[test]
    fn bad_discriminants_and_flags_are_rejected() {
        let base = golden_bytes();
        // mode byte (offset 4 + 2 + 7 + 1 = 14), guarantee (15),
        // rotate_after flag (offset 16 + 24 = 40).
        for (offset, bad) in [(14usize, 9u8), (15, 9), (40, 2)] {
            let mut bytes = base.clone();
            bytes[offset] = bad;
            assert!(
                parse(&SecretBytes::try_from_slice(&bytes).unwrap(), Tier::Ambient).is_err(),
                "expected error for byte {bad} at offset {offset}"
            );
        }
    }

    #[test]
    fn needs_rotation_reserved_key_in_map_is_refused_at_encode() {
        let mut rec = record(b"v");
        rec.metadata
            .insert(METADATA_KEY_NEEDS_ROTATION.to_owned(), "1".to_owned());
        let mut records = BTreeMap::new();
        records.insert("A".to_owned(), rec);
        assert!(encode(&records, Tier::Ambient).is_err());
    }

    #[test]
    fn unknown_reserved_keys_are_rejected_both_directions() {
        // ENVELOPE-SPEC §7.2 / Appendix A.10: writers MUST NOT emit any
        // reserved key other than needs-rotation, and parsers MUST reject
        // unknown reserved keys — the namespace is versioned by schema.
        let mut rec = record(b"v");
        rec.metadata
            .insert(format!("{METADATA_RESERVED_PREFIX}future"), "y".to_owned());
        let mut records = BTreeMap::new();
        records.insert("A".to_owned(), rec);
        assert!(encode(&records, Tier::Ambient).is_err());

        // Parse side: hand-assemble a body carrying an unknown reserved key.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(b"A");
        bytes.push(1); // tier
        bytes.push(0); // mode
        bytes.push(0); // guarantee
        bytes.extend_from_slice(&0i64.to_le_bytes());
        bytes.extend_from_slice(&0i64.to_le_bytes());
        bytes.extend_from_slice(&0i64.to_le_bytes());
        bytes.push(0); // no rotate_after
        bytes.extend_from_slice(&1u16.to_le_bytes()); // one metadata entry
        let key = format!("{METADATA_RESERVED_PREFIX}future");
        bytes.extend_from_slice(&(key.len() as u16).to_le_bytes());
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(b"y");
        bytes.extend_from_slice(&1u32.to_le_bytes()); // value
        bytes.push(b'v');
        assert!(matches!(
            parse(&SecretBytes::try_from_slice(&bytes).unwrap(), Tier::Ambient),
            Err(CoreError::HeaderParse { .. })
        ));
    }

    #[test]
    fn secret_name_charset() {
        assert!(validate_secret_name("API_KEY.v2-prod").is_ok());
        assert!(validate_secret_name(&"a".repeat(128)).is_ok());
        for bad in ["", "has space", "utf8-é", &"a".repeat(129)] {
            assert!(
                matches!(
                    validate_secret_name(bad),
                    Err(CoreError::InvalidName { .. })
                ),
                "expected InvalidName for {bad:?}"
            );
        }
    }
}
