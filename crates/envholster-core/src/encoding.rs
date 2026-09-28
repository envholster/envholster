//! Hand-written hex and base64 codecs — canonical forms only.
//!
//! The pin table (plan/04-contracts §4.6) contains no hex/base64 crate, and
//! the envelope is a hand-written canonical encoding (plan/02-envelope §3):
//! exactly one accepted byte sequence per logical content. The decoders here
//! are strict by construction — lowercase hex only; padded standard-alphabet
//! base64 with zero discarded bits — so any alternate encoding of the same
//! bytes is a parse error.
//!
//! These codecs only ever touch NON-secret bytes (recipient ids, commitments,
//! nonces, tags, age wrap blobs, cell ciphertext). Secret plaintext never
//! flows through them (plan/03-memory §3.3).

pub(crate) fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Canonical hex digit value: lowercase only (uppercase is non-canonical).
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Strict decode of exactly `expected_len` bytes of lowercase hex.
pub(crate) fn hex_decode_exact(s: &str, expected_len: usize) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() != expected_len * 2 {
        return None;
    }
    let mut out = Vec::with_capacity(expected_len);
    for pair in bytes.as_chunks::<2>().0 {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Some(out)
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard-alphabet, padded base64 (RFC 4648 §4).
pub(crate) fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(B64_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(B64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict decode: length a multiple of 4, padding only at the very end, and
/// the discarded trailing bits of the final quantum MUST be zero (a non-zero
/// tail is a second encoding of the same bytes — non-canonical, rejected).
pub(crate) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return None;
    }
    if bytes[..bytes.len() - pad].contains(&b'=') {
        return None;
    }
    let n_chunks = bytes.len() / 4;
    let mut out = Vec::with_capacity(n_chunks * 3);
    for (i, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let chunk_pad = if i + 1 == n_chunks { pad } else { 0 };
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        match chunk_pad {
            0 => {
                let c = b64_val(chunk[2])?;
                let d = b64_val(chunk[3])?;
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
            1 => {
                let c = b64_val(chunk[2])?;
                if c & 0x03 != 0 {
                    return None; // non-canonical trailing bits
                }
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            }
            2 => {
                if b & 0x0f != 0 {
                    return None; // non-canonical trailing bits
                }
                out.push((a << 2) | (b >> 4));
            }
            _ => unreachable!(),
        }
    }
    Some(out)
}

/// Lowercase-hex SHA-256 of `data` — the ONE fingerprint recipe shared by the
/// daemon's verifier registry (state.rs `hex_lower(Sha256::digest(der))`) and
/// the CLI's `approval provision-yubikey` output, exported so callers reuse
/// core's already-pinned `sha2` instead of growing their own dependency edge
/// (plan/08 §8.5 dependency-edit discipline). Non-secret input only: this
/// fingerprints PUBLIC certificate DER, never secret plaintext.
pub fn sha256_hex_lower(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_encode(Sha256::digest(data).as_slice())
}

/// HMAC-SHA-256 of `data` under `key`, lowercase hex. A keyed digest is what
/// a caller needs when the digest itself is published (a plan a client keeps
/// in a log) but the input must stay unguessable: without the key, a
/// low-entropy input cannot be confirmed by hashing candidates.
pub fn hmac_sha256_hex_lower(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA-256 accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_lower_matches_the_published_vector() {
        // FIPS 180-4 "abc" vector — proves recipe (SHA-256, lowercase hex, no
        // separators) rather than merely round-tripping our own output.
        assert_eq!(
            sha256_hex_lower(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex_lower(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_round_trip_and_strictness() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x1a]), "00ff1a");
        assert_eq!(hex_decode_exact("00ff1a", 3), Some(vec![0x00, 0xff, 0x1a]));
        assert_eq!(hex_decode_exact("00FF1a", 3), None); // uppercase rejected
        assert_eq!(hex_decode_exact("00ff1a", 2), None); // wrong length
        assert_eq!(hex_decode_exact("00ff1", 3), None);
    }

    #[test]
    fn b64_round_trip() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            let enc = b64_encode(&data);
            assert_eq!(b64_decode(&enc).as_deref(), Some(&data[..]), "len {len}");
        }
    }

    #[test]
    fn b64_strictness() {
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_decode("Zg=="), Some(b"f".to_vec()));
        assert_eq!(b64_decode("Zg"), None); // unpadded rejected
        assert_eq!(b64_decode("Zh=="), None); // non-zero trailing bits
        assert_eq!(b64_decode("Zm=g"), None); // padding not at end
        assert_eq!(b64_decode("Z g="), None); // whitespace rejected
        assert_eq!(b64_decode("QUJ*"), None); // bad alphabet
    }
}
