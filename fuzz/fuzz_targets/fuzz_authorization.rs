//! Credential (`Authorization` / `Payment-Authorization`) parsing over
//! arbitrary text.
//!
//! The input is checked twice: as the header value itself, and as the JSON a
//! credential token wraps, so the fuzzer reaches the JSON layer without
//! having to mutate base64.
//!
//! - Neither `parse_authorization` nor `extract_payment_scheme` panics.
//! - The extracted scheme is one list member of the input that starts with
//!   `Payment` followed by SP or HTAB.
//! - Parsing normalizes once: an accepted credential formats, and the result
//!   parses back to the same credential.
//! - Accepted credentials satisfy what the parser claims to validate.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::protocol::core::extract_payment_scheme;
use mpp::{base64url_encode, format_authorization, parse_authorization};
use mpp_fuzz::{assert_same, is_well_formed_echo, wire_header};

const MAX_TOKEN_LEN: usize = 16 * 1024;

fuzz_target!(|text: &str| {
    check(text);
    check(&format!("Payment {}", base64url_encode(text.as_bytes())));
});

fn check(header: &str) {
    let scheme = extract_payment_scheme(header);
    if let Some(scheme) = scheme {
        assert!(header.contains(scheme) && !scheme.contains(','));
        assert!(scheme.as_bytes()[..7].eq_ignore_ascii_case(b"payment"));
        assert!(matches!(scheme.as_bytes()[7], b' ' | b'\t'));
    }

    let Ok(credential) = parse_authorization(header) else {
        return;
    };
    let token = scheme.expect("parsed a credential without a Payment scheme")[8..].trim();
    assert!(token.len() <= MAX_TOKEN_LEN);

    let echo = &credential.challenge;
    assert!(echo.method.is_valid());
    assert_eq!(echo.header, wire_header(echo.header.as_deref()));
    assert!(is_well_formed_echo(echo));

    let formatted = format_authorization(&credential).expect("parsed credential formats");
    // Re-serialization can grow the JSON (`1e2` becomes `100.0`).
    if formatted.len() <= MAX_TOKEN_LEN {
        let reparsed = parse_authorization(&formatted).expect("formatted credential parses");
        assert_same(&reparsed, &credential);
    }
}
