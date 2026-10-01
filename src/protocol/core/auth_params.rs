//! Scanners for the `Payment` auth scheme and its auth-params (RFC 9110 §11).

use super::headers::{MAX_TOKEN_LEN, PAYMENT_SCHEME};
use crate::error::{MppError, Result};
use std::collections::HashMap;

/// Strip the Payment scheme prefix (case-insensitive) from a header value.
/// Returns the remainder of the header after the scheme, or None if not a Payment header.
pub(super) fn strip_payment_scheme(header: &str) -> Option<&str> {
    let header = header.trim_start();
    let scheme_len = PAYMENT_SCHEME.len();

    if header.len() >= scheme_len
        && header
            .get(..scheme_len)
            .is_some_and(|s| s.eq_ignore_ascii_case(PAYMENT_SCHEME))
    {
        header.get(scheme_len..)
    } else {
        None
    }
}

/// Whether `value` starts with the `Payment` scheme token (case-insensitive)
/// followed by SP or HTAB.
pub(super) fn starts_with_payment_scheme(value: &[u8]) -> bool {
    let scheme_len = PAYMENT_SCHEME.len();
    value
        .get(..scheme_len)
        .is_some_and(|token| token.eq_ignore_ascii_case(PAYMENT_SCHEME.as_bytes()))
        && matches!(value.get(scheme_len), Some(b' ' | b'\t'))
}

/// Escape a string for use in a quoted-string header value.
///
/// Only printable ASCII and HTAB are emitted as-is. Everything else is written
/// as `\uXXXX` UTF-16 code units, so the result is always a valid header value.
/// Rejects CRLF to prevent header injection attacks.
pub(super) fn escape_quoted_value(s: &str) -> Result<String> {
    if s.contains('\r') || s.contains('\n') {
        return Err(MppError::invalid_challenge_reason(
            "Header value contains invalid CRLF characters",
        ));
    }
    let mut escaped = String::with_capacity(s.len());
    for unit in s.encode_utf16() {
        match unit {
            0x005c => escaped.push_str("\\\\"),
            0x0022 => escaped.push_str("\\\""),
            0x0009 | 0x0020..=0x007e => {
                escaped.push(char::from_u32(u32::from(unit)).expect("ASCII is valid Unicode"))
            }
            _ => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{unit:04x}").expect("writing to String cannot fail");
            }
        }
    }
    Ok(escaped)
}

/// Parse key="value" pairs from an auth-param string.
///
/// This is a simple parser that handles:
/// - Quoted string values with escaped quotes
/// - Key=value without quotes for simple values
/// - Comma or space separated parameters
pub(super) fn parse_auth_params(params_str: &str) -> Result<HashMap<String, String>> {
    let mut params = HashMap::new();
    let bytes = params_str.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key_end = i;

        // RFC 9110 §11.2 allows whitespace around "=".
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        // A token that is not followed by "=" starts another auth scheme.
        if i >= bytes.len() || bytes[i] != b'=' {
            break;
        }

        // Auth-param names are case-insensitive (RFC 9110 §11.2).
        let raw_key = &params_str[key_start..key_end];
        let key = raw_key.to_ascii_lowercase();
        i += 1;

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        let value = if bytes.get(i) == Some(&b'"') {
            i += 1;
            let mut value = String::new();
            let mut segment_start = i;
            let value_end = loop {
                if i >= bytes.len() {
                    return Err(MppError::invalid_challenge_reason(
                        "Unterminated quoted-string",
                    ));
                }
                if key == "request" && value.len() + (i - segment_start) >= MAX_TOKEN_LEN {
                    return Err(MppError::invalid_challenge_reason(format!(
                        "Request parameter exceeds maximum length of {} bytes",
                        MAX_TOKEN_LEN
                    )));
                }

                match bytes[i] {
                    b'"' => break i,
                    b'\\' => {
                        value.push_str(&params_str[segment_start..i]);
                        i += 1;
                        if i >= bytes.len() {
                            return Err(MppError::invalid_challenge_reason(
                                "Unterminated quoted-string",
                            ));
                        }
                        if let Some((decoded, next)) = read_unicode_escape(params_str, i) {
                            value.push(decoded);
                            i = next;
                        } else {
                            let escaped = params_str[i..]
                                .chars()
                                .next()
                                .expect("index is on a character boundary");
                            value.push(escaped);
                            i += escaped.len_utf8();
                        }
                        segment_start = i;
                    }
                    _ => i += 1,
                }
            };
            value.push_str(&params_str[segment_start..value_end]);
            i = value_end + 1;
            value
        } else {
            let value_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b',' {
                i += 1;
            }
            if key == "request" && i - value_start > MAX_TOKEN_LEN {
                return Err(MppError::invalid_challenge_reason(format!(
                    "Request parameter exceeds maximum length of {} bytes",
                    MAX_TOKEN_LEN
                )));
            }
            params_str[value_start..i].to_string()
        };

        if params.contains_key(&key) {
            return Err(MppError::invalid_challenge_reason(format!(
                "Duplicate parameter: {}",
                raw_key
            )));
        }
        params.insert(key, value);
    }

    Ok(params)
}

fn read_unicode_escape(input: &str, at: usize) -> Option<(char, usize)> {
    let (unit, next) = read_escaped_code_unit(input, at)?;

    if !(0xD800..=0xDFFF).contains(&unit) {
        return char::from_u32(u32::from(unit)).map(|decoded| (decoded, next));
    }

    if (0xD800..=0xDBFF).contains(&unit) && input.as_bytes().get(next) == Some(&b'\\') {
        if let Some((low, after)) = read_escaped_code_unit(input, next + 1) {
            if (0xDC00..=0xDFFF).contains(&low) {
                let code =
                    0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                return char::from_u32(code).map(|decoded| (decoded, after));
            }
        }
    }

    Some((char::REPLACEMENT_CHARACTER, next))
}

fn read_escaped_code_unit(input: &str, at: usize) -> Option<(u16, usize)> {
    if input.as_bytes().get(at) != Some(&b'u') {
        return None;
    }
    let digits = input.get(at + 1..at + 5)?;
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(digits, 16)
        .ok()
        .map(|unit| (unit, at + 5))
}

/// Split a header value into individual `Payment` challenge slices.
///
/// Finds `Payment` scheme boundaries (case-insensitive per RFC 9110 §11.6.1)
/// that appear at the start of the header or after a comma separator, and
/// returns the individual challenge strings. Quoted-string contents are
/// skipped, so scheme-like text inside a parameter value is never a boundary.
pub(super) fn split_payment_challenges(header: &str) -> Vec<&str> {
    let bytes = header.as_bytes();
    let mut starts = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for (pos, &byte) in bytes.iter().enumerate() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_quotes = false;
            }
            continue;
        }
        if byte == b'"' {
            in_quotes = true;
            continue;
        }
        if !starts_with_payment_scheme(&bytes[pos..]) {
            continue;
        }
        let boundary = bytes[..pos].iter().rfind(|b| !b.is_ascii_whitespace());
        if matches!(boundary, None | Some(b',')) {
            starts.push(pos);
        }
    }

    starts
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let end = starts.get(i + 1).copied().unwrap_or(header.len());
            header[start..end].trim_end_matches([',', ' ', '\t'])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::parse_www_authenticate;

    #[test]
    fn test_split_payment_schemes_ignores_quoted() {
        // "Payment" inside a quoted value should NOT be treated as a boundary
        let header = r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30", description="Payment required""#;
        let schemes = split_payment_challenges(header);
        assert_eq!(schemes.len(), 1);
    }

    #[test]
    fn test_split_payment_schemes_leading_whitespace() {
        // Headers with leading whitespace must still be recognized
        let header =
            r#"  Payment id="a", realm="api", method="tempo", intent="charge", request="e30""#;
        let schemes = split_payment_challenges(header);
        assert_eq!(schemes.len(), 1);
        let challenge = parse_www_authenticate(schemes[0]).unwrap();
        assert_eq!(challenge.id, "a");
    }

    #[test]
    fn test_split_payment_challenges() {
        // single challenge
        let single =
            r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30""#;
        assert_eq!(split_payment_challenges(single).len(), 1);

        // two challenges, normal spacing
        let two = concat!(
            r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30", "#,
            r#"Payment id="b", realm="api", method="stripe", intent="charge", request="e30""#,
        );
        let parts = split_payment_challenges(two);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains(r#"id="a""#));
        assert!(parts[1].contains(r#"id="b""#));

        // no whitespace after comma, mixed case scheme
        let compact = concat!(
            r#"PAYMENT id="a", realm="api", method="tempo", intent="charge", request="e30","#,
            r#"payment id="b", realm="api", method="stripe", intent="charge", request="e30""#,
        );
        assert_eq!(split_payment_challenges(compact).len(), 2);

        // non-Payment scheme is dropped
        assert!(split_payment_challenges("Bearer token123").is_empty());
    }
}
