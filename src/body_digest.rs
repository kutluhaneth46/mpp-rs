//! Body digest computation and verification.
//!
//! Provides SHA-256 body digest computation for request body integrity
//! binding in payment challenges, matching the `BodyDigest` module in
//! the TypeScript SDK.
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
    let hash = Sha256::digest(body);
    let b64 = STANDARD.encode(hash);
    format!("sha-256={b64}")
}

/// Serializes `body` to JSON, then computes its SHA-256 digest.
pub fn compute_json<T: serde::Serialize>(body: &T) -> BodyDigest {
    let json = serde_json::to_vec(body).expect("failed to serialize body to JSON");
    compute(&json)
}

/// Normalize a digest to the bare `sha-256={base64}` form used by [`compute`].
///
/// Accepts both the bare form and the RFC 9530 byte sequence
/// (`sha-256=:<base64>:`), matching challenge header validation.
fn normalize_digest(digest: &str) -> Option<String> {
    let value = digest.strip_prefix("sha-256=")?;
    let value = value
        .strip_prefix(':')
        .and_then(|value| value.strip_suffix(':'))
        .unwrap_or(value);
    if value.is_empty() {
        return None;
    }
    Some(format!("sha-256={value}"))
}

/// Verifies that a digest matches the given body bytes.
///
/// `digest` may be either the bare `sha-256={base64}` form produced by
/// [`compute`] or the RFC 9530 byte sequence `sha-256=:<base64>:`. Challenge
/// parsing already accepts both; verification must too.
pub fn verify(digest: &str, body: &[u8]) -> bool {
    let Some(normalized) = normalize_digest(digest) else {
        return false;
    };
    crate::protocol::core::challenge::constant_time_eq(&compute(body), &normalized)
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

    #[test]
    fn test_verify_accepts_rfc9530_byte_sequence() {
        let body = b"hello";
        let bare = compute(body);
        let b64 = bare.strip_prefix("sha-256=").expect("bare digest prefix");
        let wrapped = format!("sha-256=:{b64}:");

        assert!(verify(&bare, body));
        assert!(verify(&wrapped, body));
        assert!(!verify(&wrapped, b"world"));
    }

    #[test]
    fn test_verify_rejects_empty_and_non_sha256() {
        assert!(!verify("", b"hello"));
        assert!(!verify("sha-256=", b"hello"));
        assert!(!verify("sha-256=::", b"hello"));
        assert!(!verify("sha-512=abc", b"hello"));
    }
}
