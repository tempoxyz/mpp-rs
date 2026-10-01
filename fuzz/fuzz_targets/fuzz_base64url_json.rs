//! base64url and canonical JSON.
//!
//! - `base64url_decode(base64url_encode(b)) == b`.
//! - `base64url_decode` never panics. It accepts everything the strict
//!   base64 and base64url engines accept, with the same result, and each
//!   accepted input has one canonical spelling: re-encoding the bytes gives
//!   the input with `=` removed and `+/` mapped to `-_`.
//! - `Base64UrlJson::from_value` keeps the value and is idempotent: decoding
//!   a canonical value and encoding it again does not change a byte. MCP
//!   relies on this to rebuild the HMAC-bound `request` from a JSON object.

#![no_main]

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use mpp::{base64url_decode, base64url_encode, Base64UrlJson};
use mpp_fuzz::json_eq;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    assert_eq!(base64url_decode(&base64url_encode(data)).unwrap(), data);

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let strict = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD].map(|e| e.decode(text));
    match base64url_decode(text) {
        Ok(bytes) => {
            let canonical = text.replace('=', "").replace('+', "-").replace('/', "_");
            assert_eq!(base64url_encode(&bytes), canonical);
            for reference in strict.into_iter().flatten() {
                assert_eq!(reference, bytes);
            }
        }
        Err(_) => assert!(strict.iter().all(Result::is_err), "rejected valid {text:?}"),
    }

    if let Ok(value) = Base64UrlJson::from_raw(text).decode_value() {
        check_canonical(&value);
    }
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        check_canonical(&value);
    }
});

fn check_canonical(value: &Value) {
    let canonical = Base64UrlJson::from_value(value).expect("JSON values canonicalize");
    let decoded = canonical.decode_value().expect("canonical JSON decodes");
    let again = Base64UrlJson::from_value(&decoded).expect("JSON values canonicalize");
    assert_eq!(
        again.raw(),
        canonical.raw(),
        "canonical form of {value} is not stable: {decoded}"
    );
    // JCS writes numbers as IEEE 754 doubles, so integers beyond 2^53 are
    // rounded: `9007199254740993` becomes `9007199254740992`.
    if !has_unsafe_integer(value) {
        assert!(json_eq(&decoded, value), "{value} decodes as {decoded}");
    }
}

fn has_unsafe_integer(value: &Value) -> bool {
    const MAX_SAFE_INTEGER: u64 = 1 << 53;
    match value {
        Value::Number(number) => {
            number.as_u64().is_some_and(|n| n > MAX_SAFE_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|n| n.unsigned_abs() > MAX_SAFE_INTEGER)
        }
        Value::Array(items) => items.iter().any(has_unsafe_integer),
        Value::Object(object) => object.values().any(has_unsafe_integer),
        _ => false,
    }
}
