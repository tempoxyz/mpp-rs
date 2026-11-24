//! Identity attestation and requirement parsing.
//!
//! - `decode` never panics, rejects tokens over `MAX_LENGTH`, and decodes
//!   only three non-empty base64url segments of JSON objects.
//! - `requirements` never panics; every requirement's type is a
//!   structured-field token and every issuer an `https` URL (`http` only on
//!   localhost).
//! - `parse_header` returns trimmed, non-empty tokens without commas.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::identity::ext::attestation::{
    decode, is_issuer, parse_header, requirements, MAX_LENGTH, REQUIRED_HEADER,
};

fuzz_target!(|input: &str| {
    if let Some(decoded) = decode(input) {
        assert!(input.len() <= MAX_LENGTH);
        assert_eq!(input.split('.').count(), 3);
        assert_eq!(
            decoded.signing_input,
            input.rsplit_once('.').unwrap().0.as_bytes()
        );
    }

    for token in parse_header([input]) {
        assert!(!token.is_empty() && !token.contains(','));
        assert_eq!(token.trim(), token);
    }

    let Ok(value) = reqwest::header::HeaderValue::from_str(input) else {
        return;
    };
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(REQUIRED_HEADER, value);
    for group in requirements(&headers) {
        assert!(!group.is_empty());
        for requirement in group {
            let kind = requirement.attestation_type.as_bytes();
            assert!(kind[0].is_ascii_alphabetic() || kind[0] == b'*', "{requirement:?}");
            if let Some(issuer) = &requirement.issuer {
                assert!(is_issuer(issuer), "{requirement:?}");
            }
        }
    }
});
