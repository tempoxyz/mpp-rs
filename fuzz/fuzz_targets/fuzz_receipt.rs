//! `Payment-Receipt` parsing and round trip.
//!
//! The input is checked as the header value itself and as the JSON a receipt
//! token wraps. It also becomes the content of a receipt built with
//! `Receipt::success`.
//!
//! - `parse_receipt` never panics.
//! - Accepted receipts are successful and carry an RFC 3339 timestamp.
//! - Parsing normalizes once: an accepted receipt formats, and the result
//!   parses back to the same receipt, extension fields included.
//! - A receipt built by the SDK parses back field for field.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::{base64url_encode, format_receipt, parse_receipt, Receipt};
use mpp_fuzz::{assert_same, is_rfc3339};

const MAX_TOKEN_LEN: usize = 16 * 1024;

fuzz_target!(|text: &str| {
    check(text);
    let extensions = check(&base64url_encode(text.as_bytes()));

    let mut receipt = Receipt::success("tempo", text)
        .with_external_id(text)
        .with_subscription_id(text);
    receipt.extensions = extensions;
    let header = format_receipt(&receipt).expect("receipts always format");
    if header.len() <= MAX_TOKEN_LEN {
        assert_same(
            &parse_receipt(&header).expect("built receipt parses"),
            &receipt,
        );
    }
});

/// Returns the extension fields of an accepted receipt.
fn check(header: &str) -> serde_json::Map<String, serde_json::Value> {
    let Ok(receipt) = parse_receipt(header) else {
        return Default::default();
    };
    assert!(header.trim().len() <= MAX_TOKEN_LEN);
    assert!(receipt.is_success());
    assert!(receipt.method.is_valid());
    assert!(is_rfc3339(&receipt.timestamp));

    let formatted = format_receipt(&receipt).expect("parsed receipt formats");
    if formatted.len() <= MAX_TOKEN_LEN {
        let reparsed = parse_receipt(&formatted).expect("formatted receipt parses");
        assert_same(&reparsed, &receipt);
    }
    receipt.extensions
}
