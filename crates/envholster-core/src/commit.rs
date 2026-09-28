//! DEK commitment (plan/02-envelope §4, c2).
//!
//! `commitment = HMAC-SHA-256(key = DEK, msg = "envholster-v1-commit")`,
//! stored in the header per cell and verified after every unwrap — closes the
//! non-committing-AEAD / invisible-salamander ambiguity for multi-recipient
//! vaults. Callers MUST surface a commitment mismatch as `AeadFailed`, never
//! as a distinct error: `AeadFailed` never distinguishes commitment from tag
//! failure (c2).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::constants::{COMMIT_LEN, DEK_COMMIT_CONTEXT};

type HmacSha256 = Hmac<Sha256>;

/// Computes the cell commitment for a DEK. The DEK is only borrowed; no copy
/// outlives the call beyond hmac's own zeroize-on-drop internals (plan/03
/// window 4 — documented irreducible residual of the RustCrypto boundary).
pub(crate) fn dek_commitment(dek: &[u8]) -> [u8; COMMIT_LEN] {
    let mut mac = HmacSha256::new_from_slice(dek).expect("HMAC-SHA-256 accepts any key length");
    mac.update(DEK_COMMIT_CONTEXT);
    let out = mac.finalize().into_bytes();
    let mut commitment = [0u8; COMMIT_LEN];
    commitment.copy_from_slice(&out);
    commitment
}

/// Constant-time verification of a header commitment against an unwrapped DEK.
pub(crate) fn verify_dek_commitment(dek: &[u8], expected: &[u8; COMMIT_LEN]) -> bool {
    let mut mac = HmacSha256::new_from_slice(dek).expect("HMAC-SHA-256 accepts any key length");
    mac.update(DEK_COMMIT_CONTEXT);
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_encode;

    // Golden vectors, computed independently (Python hmac/hashlib):
    //   HMAC-SHA-256(key = 32 x 0x00, msg = "envholster-v1-commit")
    //   HMAC-SHA-256(key = 32 x 0xff, msg = "envholster-v1-commit")
    // These pin the context string and key/msg orientation against drift.
    const GOLDEN_ZERO: &str = "710e9b91e00868f09715f6def982d8a9432408c19981773378d1fd13d4460a71";
    const GOLDEN_FF: &str = "c7d07b3ad83326650979e5e2590f6302733aec6b64e9e3171bd947ab5807d49b";

    #[test]
    fn commitment_golden_vectors() {
        assert_eq!(hex_encode(&dek_commitment(&[0u8; 32])), GOLDEN_ZERO);
        assert_eq!(hex_encode(&dek_commitment(&[0xffu8; 32])), GOLDEN_FF);
    }

    #[test]
    fn commitment_is_deterministic_and_key_sensitive() {
        let a = dek_commitment(&[7u8; 32]);
        let b = dek_commitment(&[7u8; 32]);
        let c = dek_commitment(&[8u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn verify_matches_and_rejects() {
        let dek = [42u8; 32];
        let commitment = dek_commitment(&dek);
        assert!(verify_dek_commitment(&dek, &commitment));
        let mut flipped = commitment;
        flipped[0] ^= 1;
        assert!(!verify_dek_commitment(&dek, &flipped));
        assert!(!verify_dek_commitment(&[43u8; 32], &commitment));
    }
}
