//! On-disk vault envelope — schema 1 (plan/02-envelope §3–§4).
//!
//! Canonical = exactly one accepted byte sequence per logical content: LF
//! only; one space around `=`; decimal integers with no leading zeros;
//! lowercase hex; padded standard-alphabet base64; blocks in mandated sort
//! order. Scrypt recipients OMIT the `encoding` line entirely — an empty
//! value cannot be canonically encoded (ENVELOPE-SPEC Appendix A.1).
//! Re-serializing a parsed envelope MUST be byte-identical — the
//! parser enforces this literally by re-serializing and comparing, so any
//! non-canonical variation is `HeaderParse`. This strictness is load-bearing:
//! the header-core bytes are the AAD (§4).
//!
//! Everything in this file is NON-secret: recipient public keys, commitments,
//! nonces, age wrap blobs, and cell ciphertext. Cell plaintext (HB1) never
//! appears here — it exists only inside locked buffers (plan/03-memory).

use crate::constants::{AAD_CELL_PREFIX, COMMIT_LEN, NONCE_LEN, SCHEMA, TAG_LEN};
use crate::encoding::{b64_decode, b64_encode, hex_decode_exact, hex_encode};
use crate::error::CoreError;
use crate::record::VaultUuid;
use crate::types::{
    check_class_kind, validate_label, Enrollment, EnvName, PluginName, RecipientClass,
    RecipientEntry, RecipientId, RecipientKind, Tier,
};

const MAGIC_LINE: &str = "ENVHOLSTERv1";
pub(crate) const CORE_END_LINE: &str = "-----ENVHOLSTER CORE END-----";
/// Base64 body lines are 64 chars wide, LF-terminated (plan/02-envelope §3).
const BODY_LINE_WIDTH: usize = 64;

fn parse_err(reason: impl Into<String>) -> CoreError {
    CoreError::HeaderParse {
        reason: reason.into(),
    }
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One `[cell "<env>" <tier>]` block of the header core.
///
/// `nonce` is the write-only output of the most recent save and a read-only
/// input to decrypt — it is NEVER an encryption input; a fresh nonce is drawn
/// via `getrandom::fill` immediately before each encrypt (c1, c19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CellHeader {
    pub env: EnvName,
    pub tier: Tier,
    /// HMAC-SHA-256(DEK, "envholster-v1-commit") — see `commit`.
    pub commitment: [u8; COMMIT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// Raw ciphertext byte length; AAD-covered via the header core.
    pub ct_len: u32,
    /// One single-recipient age blob per recipient, sorted by recipient id.
    pub wraps: Vec<(RecipientId, Vec<u8>)>,
}

/// The header core: every byte from offset 0 through the
/// `-----ENVHOLSTER CORE END-----` line's LF inclusive. These bytes ARE the
/// per-cell AAD prefix (plan/02-envelope §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderCore {
    pub generation: u64,
    pub vault_uuid: VaultUuid,
    /// Sorted by id ascending on disk; the serializer sorts a view, so any
    /// in-memory order serializes canonically.
    pub recipients: Vec<RecipientEntry>,
    /// Sorted by (env asc, tier asc) on disk; serializer sorts a view.
    pub cells: Vec<CellHeader>,
}

/// The parts of one cell that live OUTSIDE the header core (AEAD outputs
/// cannot be their own AAD): the detached Poly1305 tag and the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CellPayload {
    pub tag: [u8; TAG_LEN],
    /// Raw XChaCha20-Poly1305 ciphertext (base64 on disk). Ciphertext is not
    /// secret; plaintext never touches this struct.
    pub body: Vec<u8>,
}

/// A complete `secrets.holster` file: header core + tags + bodies.
/// `payloads[i]` belongs to `core.cells[i]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    pub core: HeaderCore,
    pub payloads: Vec<CellPayload>,
}

// ---------------------------------------------------------------------------
// AAD assembly (plan/02-envelope §4)
// ---------------------------------------------------------------------------

/// AAD for one cell = canonical header-core bytes ‖ `"cell:"` ‖ env ‖ `":"` ‖
/// ASCII tier digit. Recipient substitution, enrollment edits,
/// schema/downgrade flips, cell swaps, and cross-generation header/body
/// mix-and-match all change these bytes and therefore fail decryption (c2).
pub(crate) fn cell_aad(core_bytes: &[u8], env: &EnvName, tier: Tier) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(core_bytes.len() + AAD_CELL_PREFIX.len() + env.as_str().len() + 2);
    aad.extend_from_slice(core_bytes);
    aad.extend_from_slice(AAD_CELL_PREFIX.as_bytes());
    aad.extend_from_slice(env.as_str().as_bytes());
    aad.push(b':');
    aad.push(b'0' + tier.as_u8());
    aad
}

// ---------------------------------------------------------------------------
// UUID text form
// ---------------------------------------------------------------------------

pub(crate) fn uuid_to_string(uuid: &VaultUuid) -> String {
    let h = hex_encode(&uuid.0);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

pub(crate) fn uuid_from_str(s: &str) -> Option<VaultUuid> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    let lens = [8usize, 4, 4, 4, 12];
    for (part, len) in parts.iter().zip(lens) {
        if part.len() != len {
            return None;
        }
    }
    let joined = parts.concat();
    let bytes = hex_decode_exact(&joined, 16)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(VaultUuid(out))
}

// ---------------------------------------------------------------------------
// Strict integers (canonical decimal: no leading zeros, no sign, no spaces)
// ---------------------------------------------------------------------------

fn parse_u64_strict(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse::<u64>().ok()
}

fn parse_u32_strict(s: &str) -> Option<u32> {
    parse_u64_strict(s).and_then(|v| u32::try_from(v).ok())
}

fn parse_u8_strict(s: &str) -> Option<u8> {
    parse_u64_strict(s).and_then(|v| u8::try_from(v).ok())
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// `key = value` line. Values are never empty: labels are non-empty by rule
/// (ENVELOPE-SPEC Appendix A.2) and scrypt recipients omit their `encoding`
/// line entirely (Appendix A.1) instead of writing an empty value.
fn push_kv(out: &mut String, key: &str, value: &str) {
    debug_assert!(!value.is_empty(), "canonical header values are non-empty");
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(value);
    out.push('\n');
}

fn kind_field(kind: &RecipientKind) -> String {
    match kind {
        RecipientKind::X25519 => "x25519".to_owned(),
        RecipientKind::Scrypt { log_n } => format!("scrypt:{log_n}"),
        RecipientKind::Plugin { name } => format!("plugin:{}", name.as_str()),
    }
}

fn class_field(class: RecipientClass) -> &'static str {
    match class {
        RecipientClass::Hardware => "hardware",
        RecipientClass::Software => "software",
        RecipientClass::Recovery => "recovery",
    }
}

impl HeaderCore {
    /// The canonical header-core bytes — the exact disk prefix and the AAD
    /// prefix for every cell. Recipients, cells, and wraps are serialized in
    /// their mandated sort orders regardless of in-memory order.
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(MAGIC_LINE);
        out.push('\n');
        push_kv(&mut out, "schema", &SCHEMA.to_string());
        push_kv(&mut out, "generation", &self.generation.to_string());
        push_kv(&mut out, "vault-uuid", &uuid_to_string(&self.vault_uuid));

        let mut recipients: Vec<&RecipientEntry> = self.recipients.iter().collect();
        recipients.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        for recipient in recipients {
            out.push('\n');
            out.push_str(&format!("[recipient \"{}\"]\n", recipient.id.as_str()));
            push_kv(&mut out, "class", class_field(recipient.class));
            push_kv(&mut out, "kind", &kind_field(&recipient.kind));
            push_kv(&mut out, "label", &recipient.label);
            // The encoding line is OMITTED for scrypt (Appendix A.1) — there
            // is no public encoding and an empty value is non-canonical.
            if let Some(encoded) = recipient.encoded.as_deref() {
                push_kv(&mut out, "encoding", encoded);
            }
            push_kv(&mut out, "enroll", &recipient.enrollment.to_header_field());
        }

        for cell in self.sorted_cell_refs() {
            out.push('\n');
            out.push_str(&format!(
                "[cell \"{}\" {}]\n",
                cell.env.as_str(),
                cell.tier.as_u8()
            ));
            push_kv(&mut out, "commitment", &hex_encode(&cell.commitment));
            push_kv(&mut out, "nonce", &hex_encode(&cell.nonce));
            push_kv(&mut out, "ct-len", &cell.ct_len.to_string());
            let mut wraps: Vec<&(RecipientId, Vec<u8>)> = cell.wraps.iter().collect();
            wraps.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
            for (id, blob) in wraps {
                push_kv(
                    &mut out,
                    &format!("wrap {}", id.as_str()),
                    &b64_encode(blob),
                );
            }
        }

        out.push('\n');
        out.push_str(CORE_END_LINE);
        out.push('\n');
        out.into_bytes()
    }

    /// Cells in mandated (env asc, tier asc) order, without mutating `self`.
    fn sorted_cell_refs(&self) -> Vec<&CellHeader> {
        let mut cells: Vec<&CellHeader> = self.cells.iter().collect();
        cells.sort_by(|a, b| (&a.env, a.tier).cmp(&(&b.env, b.tier)));
        cells
    }

    /// Indices of `self.cells` in mandated order — used to keep tags and
    /// bodies aligned with their cells when serializing.
    fn sorted_cell_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..self.cells.len()).collect();
        indices.sort_by(|&a, &b| {
            (&self.cells[a].env, self.cells[a].tier).cmp(&(&self.cells[b].env, self.cells[b].tier))
        });
        indices
    }
}

impl Envelope {
    /// The exact `secrets.holster` disk bytes.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        assert_eq!(
            self.core.cells.len(),
            self.payloads.len(),
            "envelope invariant: one payload per cell"
        );
        let mut out = self.core.canonical_bytes();
        let order = self.core.sorted_cell_indices();

        let mut tags = String::from("[tags]\n");
        for &i in &order {
            let cell = &self.core.cells[i];
            tags.push_str(&format!(
                "tag {}:{} = {}\n",
                cell.env.as_str(),
                cell.tier.as_u8(),
                hex_encode(&self.payloads[i].tag)
            ));
        }
        out.extend_from_slice(tags.as_bytes());

        for &i in &order {
            let cell = &self.core.cells[i];
            let mut body = format!("\n[body \"{}\" {}]\n", cell.env.as_str(), cell.tier.as_u8());
            let b64 = b64_encode(&self.payloads[i].body);
            for chunk in b64.as_bytes().chunks(BODY_LINE_WIDTH) {
                body.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
                body.push('\n');
            }
            out.extend_from_slice(body.as_bytes());
        }
        out
    }

    /// Strict parse of the exact disk bytes. Any deviation from the canonical
    /// serialization — ordering, spacing, casing, encoding, trailing bytes —
    /// is `HeaderParse`; schema and recipient-kind forward-compat errors keep
    /// their dedicated variants.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, CoreError> {
        let text = std::str::from_utf8(bytes).map_err(|_| parse_err("vault is not UTF-8"))?;
        if text.is_empty() {
            return Err(parse_err("empty file"));
        }
        if text.contains('\r') {
            return Err(parse_err("carriage returns are not canonical (LF only)"));
        }
        if !text.ends_with('\n') {
            return Err(parse_err("missing final newline"));
        }

        let mut lines = Lines { rest: text };

        // --- preamble ---
        if lines.next_line()? != MAGIC_LINE {
            return Err(parse_err("missing ENVHOLSTERv1 magic"));
        }
        let schema_value = kv_value(lines.next_line()?, "schema")?;
        let schema = parse_u32_strict(schema_value)
            .ok_or_else(|| parse_err("schema is not a canonical integer"))?;
        if schema != SCHEMA {
            return Err(CoreError::UnsupportedSchema {
                found: schema,
                supported: SCHEMA,
            });
        }
        let generation = parse_u64_strict(kv_value(lines.next_line()?, "generation")?)
            .ok_or_else(|| parse_err("generation is not a canonical u64"))?;
        let vault_uuid = uuid_from_str(kv_value(lines.next_line()?, "vault-uuid")?)
            .ok_or_else(|| parse_err("vault-uuid is not a lowercase hyphenated uuid"))?;

        // --- recipient and cell blocks, then the core end marker ---
        let mut recipients: Vec<RecipientEntry> = Vec::new();
        let mut cells: Vec<CellHeader> = Vec::new();
        let mut seen_cell = false;
        loop {
            if !lines.next_line()?.is_empty() {
                return Err(parse_err("expected blank line before block"));
            }
            let line = lines.next_line()?;
            if line == CORE_END_LINE {
                break;
            }
            if let Some(id) = block_header(line, "recipient") {
                if seen_cell {
                    return Err(parse_err("recipient block after cell block"));
                }
                let entry = parse_recipient_block(id, &mut lines)?;
                if let Some(last) = recipients.last() {
                    match last.id.as_str().cmp(entry.id.as_str()) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => {
                            return Err(parse_err(format!(
                                "duplicate recipient id {}",
                                entry.id.as_str()
                            )))
                        }
                        std::cmp::Ordering::Greater => {
                            return Err(parse_err("recipient blocks not sorted by id"))
                        }
                    }
                }
                recipients.push(entry);
            } else if let Some((env, tier)) = cell_block_header(line, "cell")? {
                seen_cell = true;
                let cell = parse_cell_block(env, tier, &recipients, &mut lines)?;
                if let Some(last) = cells.last() {
                    match (&last.env, last.tier).cmp(&(&cell.env, cell.tier)) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => {
                            return Err(parse_err(format!(
                                "duplicate cell {}:{}",
                                cell.env.as_str(),
                                cell.tier.as_u8()
                            )))
                        }
                        std::cmp::Ordering::Greater => {
                            return Err(parse_err("cell blocks not sorted by (env, tier)"))
                        }
                    }
                }
                cells.push(cell);
            } else {
                return Err(parse_err(format!("unexpected line {line:?}")));
            }
        }

        // --- tag section, immediately after the core end marker ---
        if lines.next_line()? != "[tags]" {
            return Err(parse_err("expected [tags] after core end marker"));
        }
        let mut tags: Vec<[u8; TAG_LEN]> = Vec::with_capacity(cells.len());
        for cell in &cells {
            let line = lines.next_line()?;
            let expected_key = format!("tag {}:{}", cell.env.as_str(), cell.tier.as_u8());
            let value = kv_value(line, &expected_key)?;
            let tag_bytes = hex_decode_exact(value, TAG_LEN)
                .ok_or_else(|| parse_err("tag is not 32 lowercase hex chars"))?;
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&tag_bytes);
            tags.push(tag);
        }

        // --- bodies, in cell order ---
        let mut payloads: Vec<CellPayload> = Vec::with_capacity(cells.len());
        for (cell, tag) in cells.iter().zip(tags) {
            if !lines.next_line()?.is_empty() {
                return Err(parse_err("expected blank line before body block"));
            }
            let header = lines.next_line()?;
            let expected = format!("[body \"{}\" {}]", cell.env.as_str(), cell.tier.as_u8());
            if header != expected {
                return Err(parse_err("body blocks must follow cell order"));
            }
            let mut b64 = String::new();
            let mut prev_len: Option<usize> = None;
            while let Some(line) = lines.peek_line() {
                if line.is_empty() {
                    break;
                }
                if let Some(prev) = prev_len {
                    if prev != BODY_LINE_WIDTH {
                        return Err(parse_err("body lines before the last must be 64 chars"));
                    }
                }
                if line.len() > BODY_LINE_WIDTH {
                    return Err(parse_err("body lines are at most 64 chars"));
                }
                prev_len = Some(line.len());
                b64.push_str(line);
                lines.next_line()?;
            }
            let body = b64_decode(&b64).ok_or_else(|| parse_err("body is not canonical base64"))?;
            if body.len() as u64 != u64::from(cell.ct_len) {
                return Err(parse_err(format!(
                    "body length does not match ct-len for cell {}:{}",
                    cell.env.as_str(),
                    cell.tier.as_u8()
                )));
            }
            payloads.push(CellPayload { tag, body });
        }

        if !lines.rest.is_empty() {
            return Err(parse_err("trailing bytes after last body"));
        }

        let envelope = Envelope {
            core: HeaderCore {
                generation,
                vault_uuid,
                recipients,
                cells,
            },
            payloads,
        };

        // The load-bearing canonicality gate: re-serializing MUST reproduce
        // the input byte-for-byte (plan/02-envelope §3) — this catches every
        // remaining non-canonical variation in one place.
        if envelope.to_bytes() != bytes {
            return Err(parse_err(
                "input is not the canonical serialization of its content",
            ));
        }
        Ok(envelope)
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// LF-terminated line cursor over the full file text.
struct Lines<'a> {
    rest: &'a str,
}

impl<'a> Lines<'a> {
    fn next_line(&mut self) -> Result<&'a str, CoreError> {
        match self.rest.split_once('\n') {
            Some((line, rest)) => {
                self.rest = rest;
                Ok(line)
            }
            None => Err(parse_err("unexpected end of file")),
        }
    }

    fn peek_line(&self) -> Option<&'a str> {
        self.rest.split_once('\n').map(|(line, _)| line)
    }
}

/// Strict `key = value` line: exactly one space on each side of `=`, value
/// non-empty. The value must not start or end with whitespace (that would be
/// a second spelling of the same content).
fn kv_value<'a>(line: &'a str, key: &str) -> Result<&'a str, CoreError> {
    let rest = line
        .strip_prefix(key)
        .ok_or_else(|| parse_err(format!("expected {key:?} line, found {line:?}")))?;
    let value = rest
        .strip_prefix(" = ")
        .ok_or_else(|| parse_err(format!("expected {key:?} line, found {line:?}")))?;
    if value.is_empty() || value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
        return Err(parse_err(format!("non-canonical spacing in {key:?} line")));
    }
    Ok(value)
}

/// `[<block> "<name>"]` → `name`.
fn block_header<'a>(line: &'a str, block: &str) -> Option<&'a str> {
    line.strip_prefix('[')?
        .strip_suffix("\"]")?
        .strip_prefix(block)?
        .strip_prefix(" \"")
}

/// `[<block> "<env>" <tier>]` → `(EnvName, Tier)`; `Ok(None)` when the line
/// is not this block kind at all.
fn cell_block_header(line: &str, block: &str) -> Result<Option<(EnvName, Tier)>, CoreError> {
    let inner = match line
        .strip_prefix('[')
        .and_then(|l| l.strip_suffix(']'))
        .and_then(|l| l.strip_prefix(block))
        .and_then(|l| l.strip_prefix(" \""))
    {
        Some(inner) => inner,
        None => return Ok(None),
    };
    let (env_str, tier_str) = inner
        .split_once("\" ")
        .ok_or_else(|| parse_err(format!("malformed {block} block header")))?;
    let env = EnvName::parse(env_str)
        .map_err(|_| parse_err(format!("invalid environment name in {block} block header")))?;
    let tier_bytes = tier_str.as_bytes();
    if tier_bytes.len() != 1 {
        return Err(parse_err(format!("malformed tier in {block} block header")));
    }
    let tier = Tier::try_from_u8(tier_bytes[0].wrapping_sub(b'0'))
        .ok_or_else(|| parse_err(format!("tier out of range in {block} block header")))?;
    Ok(Some((env, tier)))
}

fn parse_class(value: &str) -> Result<RecipientClass, CoreError> {
    match value {
        "hardware" => Ok(RecipientClass::Hardware),
        "software" => Ok(RecipientClass::Software),
        "recovery" => Ok(RecipientClass::Recovery),
        other => Err(parse_err(format!("unknown recipient class {other:?}"))),
    }
}

/// Kind field. Unknown kinds fail open() with `UnknownRecipientKind` — never
/// skipped or guessed (plan/02-envelope §1); plugin names are
/// charset-validated and allowlisted here (RUSTSEC-2024-0433).
fn parse_kind(value: &str) -> Result<RecipientKind, CoreError> {
    if value == "x25519" {
        return Ok(RecipientKind::X25519);
    }
    if let Some(log_n) = value.strip_prefix("scrypt:") {
        let log_n = parse_u8_strict(log_n)
            .filter(|&n| n > 0 && n < 64)
            .ok_or_else(|| parse_err("scrypt log_n is not a canonical work factor"))?;
        return Ok(RecipientKind::Scrypt { log_n });
    }
    if let Some(name) = value.strip_prefix("plugin:") {
        let name = match PluginName::parse(name) {
            Ok(name) => name,
            Err(CoreError::PluginNotAllowed(name)) => {
                return Err(CoreError::PluginNotAllowed(name))
            }
            Err(_) => return Err(parse_err("plugin name violates [a-z0-9-]{1,32}")),
        };
        return Ok(RecipientKind::Plugin { name });
    }
    Err(CoreError::UnknownRecipientKind {
        kind: value.to_owned(),
    })
}

fn parse_recipient_block(id: &str, lines: &mut Lines<'_>) -> Result<RecipientEntry, CoreError> {
    let id = RecipientId::parse(id)
        .map_err(|_| parse_err("recipient id is not 16 lowercase hex chars"))?;
    let class = parse_class(kv_value(lines.next_line()?, "class")?)?;
    let kind = parse_kind(kv_value(lines.next_line()?, "kind")?)?;
    let label = kv_value(lines.next_line()?, "label")?.to_owned();
    validate_label(&label).map_err(|_| parse_err("invalid recipient label"))?;
    // The encoding line is present iff the kind is not scrypt (ENVELOPE-SPEC
    // §4.4, Appendix A.1). A scrypt block containing an encoding line, or a
    // non-scrypt block missing one, fails as "expected ... line" here.
    let encoding = match &kind {
        RecipientKind::Scrypt { .. } => String::new(),
        _ => kv_value(lines.next_line()?, "encoding")?.to_owned(),
    };
    let enrollment = Enrollment::parse_header_field(kv_value(lines.next_line()?, "enroll")?)?;

    check_class_kind(class, &kind).map_err(parse_err)?;

    let encoded = match &kind {
        RecipientKind::Scrypt { .. } => None,
        RecipientKind::X25519 => {
            let recipient = encoding
                .parse::<age::x25519::Recipient>()
                .map_err(|_| parse_err("encoding is not a valid x25519 age recipient"))?;
            if recipient.to_string() != encoding {
                return Err(parse_err("encoding is not in canonical form"));
            }
            if RecipientId::derive(&encoding) != id {
                return Err(parse_err("recipient id does not match its encoding"));
            }
            Some(encoding)
        }
        RecipientKind::Plugin { name } => {
            let recipient = encoding
                .parse::<age::plugin::Recipient>()
                .map_err(|_| parse_err("encoding is not a valid age plugin recipient"))?;
            if recipient.plugin() != name.as_str() {
                return Err(parse_err("encoding plugin does not match declared kind"));
            }
            if recipient.to_string() != encoding {
                return Err(parse_err("encoding is not in canonical form"));
            }
            if RecipientId::derive(&encoding) != id {
                return Err(parse_err("recipient id does not match its encoding"));
            }
            Some(encoding)
        }
    };

    Ok(RecipientEntry {
        id,
        class,
        kind,
        label,
        encoded,
        enrollment,
    })
}

fn parse_cell_block(
    env: EnvName,
    tier: Tier,
    recipients: &[RecipientEntry],
    lines: &mut Lines<'_>,
) -> Result<CellHeader, CoreError> {
    let commitment_hex = kv_value(lines.next_line()?, "commitment")?;
    let commitment_bytes = hex_decode_exact(commitment_hex, COMMIT_LEN)
        .ok_or_else(|| parse_err("commitment is not 64 lowercase hex chars"))?;
    let mut commitment = [0u8; COMMIT_LEN];
    commitment.copy_from_slice(&commitment_bytes);

    let nonce_hex = kv_value(lines.next_line()?, "nonce")?;
    let nonce_bytes = hex_decode_exact(nonce_hex, NONCE_LEN)
        .ok_or_else(|| parse_err("nonce is not 48 lowercase hex chars"))?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);

    let ct_len = parse_u32_strict(kv_value(lines.next_line()?, "ct-len")?)
        .ok_or_else(|| parse_err("ct-len is not a canonical u32"))?;

    let mut wraps: Vec<(RecipientId, Vec<u8>)> = Vec::new();
    while let Some(line) = lines.peek_line() {
        if !line.starts_with("wrap ") {
            break;
        }
        let line = lines.next_line()?;
        let rest = &line["wrap ".len()..];
        let (id_str, _) = rest
            .split_once(' ')
            .ok_or_else(|| parse_err("malformed wrap line"))?;
        let value = kv_value(line, &format!("wrap {id_str}"))?;
        let id = RecipientId::parse(id_str)
            .map_err(|_| parse_err("wrap recipient id is not 16 lowercase hex chars"))?;
        if !recipients.iter().any(|r| r.id == id) {
            return Err(parse_err(format!(
                "wrap references undeclared recipient {}",
                id.as_str()
            )));
        }
        if let Some((last_id, _)) = wraps.last() {
            match last_id.as_str().cmp(id.as_str()) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(parse_err(format!("duplicate wrap for {}", id.as_str())))
                }
                std::cmp::Ordering::Greater => {
                    return Err(parse_err("wrap lines not sorted by recipient id"))
                }
            }
        }
        let blob =
            b64_decode(value).ok_or_else(|| parse_err("wrap blob is not canonical base64"))?;
        wraps.push((id, blob));
    }
    if wraps.is_empty() {
        return Err(parse_err(format!(
            "cell {}:{} has no wraps",
            env.as_str(),
            tier.as_u8()
        )));
    }

    Ok(CellHeader {
        env,
        tier,
        commitment,
        nonce,
        ct_len,
        wraps,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EnvSelector;
    use std::collections::BTreeMap;

    fn x25519_entry(class: RecipientClass, label: &str, enrollment: Enrollment) -> RecipientEntry {
        let encoded = age::x25519::Identity::generate().to_public().to_string();
        RecipientEntry::from_encoded(&encoded, class, label.to_owned(), enrollment).unwrap()
    }

    fn named(pairs: &[(&str, Tier)]) -> Enrollment {
        let mut map = BTreeMap::new();
        for (env, tier) in pairs {
            map.insert(EnvName::parse(env).unwrap(), *tier);
        }
        Enrollment(EnvSelector::Named(map))
    }

    fn all(max_tier: Tier) -> Enrollment {
        Enrollment(EnvSelector::All { max_tier })
    }

    /// A structurally complete two-cell test envelope: a recovery recipient,
    /// a software recipient, a scrypt recipient; cells (base,1) and (prod,3).
    fn sample_envelope() -> Envelope {
        let recovery = x25519_entry(RecipientClass::Recovery, "paper key", all(Tier::Critical));
        let software = x25519_entry(RecipientClass::Software, "laptop", all(Tier::Ambient));
        let scrypt = RecipientEntry::scrypt(
            "team passphrase".to_owned(),
            named(&[("dev", Tier::Ambient)]),
            20,
        )
        .unwrap();

        let mut wrap_ids: Vec<RecipientId> =
            vec![recovery.id.clone(), software.id.clone(), scrypt.id.clone()];
        wrap_ids.sort();

        let make_cell = |env: &str, tier: Tier, seed: u8| CellHeader {
            env: EnvName::parse(env).unwrap(),
            tier,
            commitment: [seed; COMMIT_LEN],
            nonce: [seed.wrapping_add(1); NONCE_LEN],
            ct_len: 20,
            wraps: wrap_ids
                .iter()
                .map(|id| (id.clone(), vec![seed, 1, 2, 3, id.as_str().as_bytes()[0]]))
                .collect(),
        };

        // Stored pre-sorted by id (the disk order), so struct comparisons
        // against a parsed envelope line up; the serializer sorts a view
        // anyway (see `serialization_order_is_canonical_regardless_of_memory_order`).
        let mut recipients = vec![recovery, software, scrypt];
        recipients.sort_by(|a, b| a.id.cmp(&b.id));

        Envelope {
            core: HeaderCore {
                generation: 7,
                vault_uuid: VaultUuid(
                    *b"\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef",
                ),
                recipients,
                cells: vec![
                    make_cell("base", Tier::Ambient, 0x11),
                    make_cell("prod", Tier::Critical, 0x22),
                ],
            },
            payloads: vec![
                CellPayload {
                    tag: [0xaa; TAG_LEN],
                    body: vec![0x5a; 20],
                },
                CellPayload {
                    tag: [0xbb; TAG_LEN],
                    body: vec![0xa5; 20],
                },
            ],
        }
    }

    #[test]
    fn canonical_round_trip_is_byte_identical() {
        let envelope = sample_envelope();
        let bytes = envelope.to_bytes();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(parsed, envelope);
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(parsed.core.generation, 7);
        // The core bytes end exactly at the END marker's LF.
        let core = parsed.core.canonical_bytes();
        assert!(bytes.starts_with(&core));
        assert!(core.ends_with(format!("{CORE_END_LINE}\n").as_bytes()));
    }

    #[test]
    fn serialization_order_is_canonical_regardless_of_memory_order() {
        let mut envelope = sample_envelope();
        envelope.core.recipients.reverse();
        envelope.core.cells.reverse();
        envelope.payloads.reverse();
        for cell in &mut envelope.core.cells {
            cell.wraps.reverse();
        }
        let reference = sample_envelope();
        // Same logical content (recipients differ only by generated keys, so
        // rebuild instead of comparing to `reference` directly): check that a
        // shuffled copy of THE SAME envelope serializes identically.
        let mut shuffled = reference.clone();
        shuffled.core.recipients.reverse();
        shuffled.core.cells.reverse();
        shuffled.payloads.reverse();
        for cell in &mut shuffled.core.cells {
            cell.wraps.reverse();
        }
        assert_eq!(shuffled.to_bytes(), reference.to_bytes());
    }

    #[test]
    fn aad_is_core_bytes_plus_cell_suffix() {
        let envelope = sample_envelope();
        let core = envelope.core.canonical_bytes();
        let aad = cell_aad(&core, &EnvName::parse("prod").unwrap(), Tier::Critical);
        assert!(aad.starts_with(&core));
        assert!(aad.ends_with(b"cell:prod:3"));
        assert_eq!(aad.len(), core.len() + "cell:prod:3".len());

        // AAD is stable across a parse round-trip…
        let parsed = Envelope::parse(&envelope.to_bytes()).unwrap();
        assert_eq!(
            cell_aad(
                &parsed.core.canonical_bytes(),
                &EnvName::parse("prod").unwrap(),
                Tier::Critical
            ),
            aad
        );

        // …and every core mutation (here: generation) changes it.
        let mut bumped = envelope.clone();
        bumped.core.generation += 1;
        assert_ne!(
            cell_aad(
                &bumped.core.canonical_bytes(),
                &EnvName::parse("prod").unwrap(),
                Tier::Critical
            ),
            aad
        );
    }

    #[test]
    fn non_canonical_variants_are_rejected() {
        let bytes = sample_envelope().to_bytes();
        let text = String::from_utf8(bytes.clone()).unwrap();

        let mutations: Vec<(String, String)> = vec![
            ("trailing newline".into(), format!("{text}\n")),
            ("crlf".into(), text.replace('\n', "\r\n")),
            (
                "leading-zero generation".into(),
                text.replace("generation = 7", "generation = 07"),
            ),
            (
                "extra spacing".into(),
                text.replace("generation = 7", "generation  = 7"),
            ),
            (
                "extra blank line".into(),
                text.replacen("\n[tags]", "\n\n[tags]", 1),
            ),
            ("uppercase hex tag".into(), text.replace("aaaa", "AAAA")),
        ];
        for (name, mutated) in mutations {
            assert!(
                matches!(
                    Envelope::parse(mutated.as_bytes()),
                    Err(CoreError::HeaderParse { .. })
                ),
                "expected HeaderParse for mutation: {name}"
            );
        }
        // Truncation (no final newline / missing sections) also fails.
        assert!(Envelope::parse(&bytes[..bytes.len() - 1]).is_err());
        assert!(Envelope::parse(b"").is_err());
    }

    #[test]
    fn forward_compat_errors_keep_their_variants() {
        let text = String::from_utf8(sample_envelope().to_bytes()).unwrap();

        let newer = text.replace("schema = 1", "schema = 2");
        assert!(matches!(
            Envelope::parse(newer.as_bytes()),
            Err(CoreError::UnsupportedSchema {
                found: 2,
                supported: 1
            })
        ));

        let unknown_kind = text.replacen("kind = x25519", "kind = pq-mlkem768", 1);
        assert!(matches!(
            Envelope::parse(unknown_kind.as_bytes()),
            Err(CoreError::UnknownRecipientKind { kind }) if kind == "pq-mlkem768"
        ));

        let bad_plugin = text.replacen("kind = x25519", "kind = plugin:evil", 1);
        assert!(matches!(
            Envelope::parse(bad_plugin.as_bytes()),
            Err(CoreError::PluginNotAllowed(name)) if name == "evil"
        ));
    }

    #[test]
    fn tampered_ids_and_lengths_are_rejected() {
        let envelope = sample_envelope();
        let text = String::from_utf8(envelope.to_bytes()).unwrap();

        // Flip the declared id of an x25519 recipient block: the id/encoding
        // binding breaks. (A scrypt id is random and carries no encoding, so
        // its tamper is caught by AAD at decrypt, not at parse — deliberately
        // not tested here.)
        let x25519_id = envelope
            .core
            .recipients
            .iter()
            .find(|r| matches!(r.kind, RecipientKind::X25519))
            .unwrap()
            .id
            .as_str();
        let tampered = text.replace(x25519_id, "0000000000000000");
        assert!(matches!(
            Envelope::parse(tampered.as_bytes()),
            Err(CoreError::HeaderParse { .. })
        ));

        // ct-len no longer matching the body is a parse error.
        let bad_len = text.replace("ct-len = 20", "ct-len = 21");
        assert!(matches!(
            Envelope::parse(bad_len.as_bytes()),
            Err(CoreError::HeaderParse { .. })
        ));
    }

    #[test]
    fn scrypt_encoding_line_presence_rules() {
        // ENVELOPE-SPEC §4.4 / Appendix A.1: the encoding line is OMITTED for
        // scrypt and MANDATORY for every other kind.
        let envelope = sample_envelope();
        let text = String::from_utf8(envelope.to_bytes()).unwrap();

        // The serialized scrypt block has no encoding line at all.
        let scrypt_block = text
            .split("\n\n")
            .find(|block| block.contains("kind = scrypt:20"))
            .expect("scrypt block");
        assert!(!scrypt_block.contains("encoding"));

        // Injecting an encoding line into the scrypt block is a parse error.
        let with_encoding = text.replacen(
            "kind = scrypt:20\nlabel = team passphrase\n",
            "kind = scrypt:20\nlabel = team passphrase\nencoding = age1bogus\n",
            1,
        );
        assert_ne!(with_encoding, text);
        assert!(matches!(
            Envelope::parse(with_encoding.as_bytes()),
            Err(CoreError::HeaderParse { .. })
        ));

        // Removing an x25519 block's encoding line is a parse error.
        let encoding_line_start = text.find("\nencoding = ").unwrap() + 1;
        let encoding_line_end =
            text[encoding_line_start..].find('\n').unwrap() + encoding_line_start + 1;
        let without_encoding = format!(
            "{}{}",
            &text[..encoding_line_start],
            &text[encoding_line_end..]
        );
        assert!(matches!(
            Envelope::parse(without_encoding.as_bytes()),
            Err(CoreError::HeaderParse { .. })
        ));
    }

    #[test]
    fn generation_counter_round_trips_at_u64_extremes() {
        let mut envelope = sample_envelope();
        envelope.core.generation = u64::MAX;
        let parsed = Envelope::parse(&envelope.to_bytes()).unwrap();
        assert_eq!(parsed.core.generation, u64::MAX);
    }

    #[test]
    fn uuid_text_form_round_trips() {
        let uuid = VaultUuid([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ]);
        let s = uuid_to_string(&uuid);
        assert_eq!(s, "01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(uuid_from_str(&s), Some(uuid));
        assert_eq!(uuid_from_str("01234567-89AB-cdef-0123-456789abcdef"), None);
        assert_eq!(uuid_from_str("0123456789abcdef0123456789abcdef"), None);
    }

    #[test]
    fn empty_body_cell_round_trips() {
        // ct_len = 0 is grammatically valid (no base64 lines); stage B save
        // validation decides whether it is semantically reachable.
        let mut envelope = sample_envelope();
        envelope.core.cells[0].ct_len = 0;
        envelope.payloads[0].body.clear();
        let bytes = envelope.to_bytes();
        assert_eq!(Envelope::parse(&bytes).unwrap(), envelope);
    }
}
