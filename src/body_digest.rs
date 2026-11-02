//! Body digest computation and verification.
//!
//! Provides SHA-256 body digest computation for request body integrity
//! binding in payment challenges. Generation matches the `BodyDigest` module
//! in the TypeScript SDK; verification also accepts the RFC 9530 SHA-256
//! byte-sequence form.
//!
//! # Examples
//!
//! ```
//! use mpp::body_digest;
//!
//! let digest = body_digest::compute(b"hello");
//! assert!(body_digest::verify(&digest, b"hello"));
//! ```

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

/// A body digest string in the format `"sha-256={base64}"`.
pub type BodyDigest = String;

/// Computes a SHA-256 digest of the given body bytes.
///
/// Returns a digest string in the format `"sha-256={base64}"`.
pub fn compute(body: &[u8]) -> BodyDigest {
    format!("sha-256={}", compute_hash(body))
}

fn compute_hash(body: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(body))
}

/// Serializes `body` to JSON, then computes its SHA-256 digest.
pub fn compute_json<T: serde::Serialize>(body: &T) -> BodyDigest {
    let json = serde_json::to_vec(body).expect("failed to serialize body to JSON");
    compute(&json)
}

/// Verifies that a digest matches the given body bytes.
///
/// Accepts both `sha-256={base64}` and the RFC 9530 SHA-256 byte-sequence
/// form `sha-256=:{base64}:`.
pub fn verify(digest: &str, body: &[u8]) -> bool {
    let Some(hash) = digest.strip_prefix("sha-256=") else {
        return false;
    };
    let hash = hash
        .strip_prefix(':')
        .and_then(|hash| hash.strip_suffix(':'))
        .unwrap_or(hash);
    crate::protocol::core::challenge::constant_time_eq(&compute_hash(body), hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute() {
        let digest = compute(b"hello");
        assert!(digest.starts_with("sha-256="));
    }

    #[test]
    fn test_verify() {
        let digest = compute(b"hello");
        assert!(verify(&digest, b"hello"));
        assert!(!verify(&digest, b"world"));
    }

    #[test]
    fn test_verify_rfc9530_byte_sequence() {
        for (digest, body) in [
            (
                "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:",
                b"hello".as_slice(),
            ),
            (
                "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
                b"".as_slice(),
            ),
        ] {
            assert!(verify(digest, body));
            assert!(!verify(digest, b"changed body"));
        }
    }

    #[test]
    fn test_verify_rejects_malformed_byte_sequences() {
        let hash = "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
        for digest in [
            format!("sha-256=:{hash}"),
            format!("sha-256={hash}:"),
            format!("sha-256=::{hash}::"),
            format!("sha-256=:{hash}::"),
            format!("sha-256=::{hash}:"),
            format!("SHA-256=:{hash}:"),
            format!("sha-512=:{hash}:"),
            format!(" sha-256=:{hash}:"),
            format!("sha-256=:{hash}: "),
            format!("sha-256=:{hash}:;param=1"),
            format!("sha-256=:{hash}:, sha-512=:{hash}:"),
            "sha-256=::".to_string(),
        ] {
            assert!(!verify(&digest, b"hello"), "accepted {digest:?}");
        }
    }

    #[test]
    fn test_round_trip() {
        let body = b"some request body";
        let digest = compute(body);
        assert!(verify(&digest, body));
    }

    #[test]
    fn test_compute_json() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct Body {
            amount: String,
        }

        let body = Body {
            amount: "1000".to_string(),
        };
        let digest = compute_json(&body);
        assert!(digest.starts_with("sha-256="));

        // Should match computing from the raw JSON bytes
        let json = serde_json::to_vec(&body).expect("test body should serialize");
        assert!(verify(&digest, &json));
    }

    #[test]
    fn test_empty_body() {
        let digest = compute(b"");
        assert!(verify(&digest, b""));
        assert!(!verify(&digest, b"x"));
    }
}
