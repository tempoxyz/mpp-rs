//! Header parsing and formatting functions for Web Payment Auth.
//!
//! This module provides functions to parse and format the HTTP headers used
//! in the Web Payment Auth protocol:
//!
//! - `WWW-Authenticate: Payment ...` - Challenge from server
//! - `Authorization: Payment ...` - Credential from client  
//! - `Payment-Receipt: ...` - Receipt from server
//!
//! The parser is implemented without regex for minimal dependencies.

use super::challenge::{PaymentChallenge, PaymentCredential, PaymentReceipt};
use super::types::{base64url_decode, base64url_encode, Base64UrlJson, IntentName, MethodName};
use crate::error::{MppError, Result};
use std::collections::HashMap;

/// Maximum length for base64url-encoded tokens to prevent memory exhaustion DoS.
const MAX_TOKEN_LEN: usize = 16 * 1024;

/// Escape a string for use in a quoted-string header value.
/// Rejects CRLF to prevent header injection attacks.
fn escape_quoted_value(s: &str) -> Result<String> {
    if s.contains('\r') || s.contains('\n') {
        return Err(MppError::InvalidChallenge(
            "Header value contains invalid CRLF characters".to_string(),
        ));
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Header name for payment challenges (from server)
pub const WWW_AUTHENTICATE_HEADER: &str = "www-authenticate";

/// Header name for payment credentials (from client)
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// Header name for payment receipts (from server)
pub const PAYMENT_RECEIPT_HEADER: &str = "payment-receipt";

/// Scheme identifier for the Payment authentication scheme
pub const PAYMENT_SCHEME: &str = "Payment";

/// Parse key="value" pairs from an auth-param string.
///
/// This is a simple parser that handles:
/// - Quoted string values with escaped quotes
/// - Key=value without quotes for simple values
/// - Comma or space separated parameters
fn parse_auth_params(params_str: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    let chars: Vec<char> = params_str.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        while i < chars.len() && (chars[i].is_whitespace() || chars[i] == ',') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }

        let key_start = i;
        while i < chars.len() && chars[i] != '=' && !chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            while i < chars.len() && !chars[i].is_whitespace() && chars[i] != ',' {
                i += 1;
            }
            continue;
        }

        let key: String = chars[key_start..i].iter().collect();
        i += 1;

        if i >= chars.len() {
            break;
        }

        let value = if chars[i] == '"' {
            i += 1;
            let mut value = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    value.push(chars[i]);
                } else {
                    value.push(chars[i]);
                }
                i += 1;
            }
            if i < chars.len() {
                i += 1;
            }
            value
        } else {
            let value_start = i;
            while i < chars.len() && !chars[i].is_whitespace() && chars[i] != ',' {
                i += 1;
            }
            chars[value_start..i].iter().collect()
        };

        params.insert(key, value);
    }

    params
}

/// Parse a single WWW-Authenticate header into a PaymentChallenge.
///
/// Format: `Payment id="<id>", realm="<realm>", method="<method>", intent="<intent>", request="<base64url-json>"`
///
/// Parsing is case-insensitive for the scheme name per RFC 7235.
///
/// # Examples
///
/// ```
/// use mpay::protocol::core::parse_www_authenticate;
///
/// let header = r#"Payment id="abc123", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwMCJ9""#;
/// let challenge = parse_www_authenticate(header).unwrap();
/// assert_eq!(challenge.id, "abc123");
/// ```
pub fn parse_www_authenticate(header: &str) -> Result<PaymentChallenge> {
    // Trim leading whitespace (tolerate per RFC 7235)
    let header = header.trim_start();

    // Case-insensitive scheme matching using strip_prefix to avoid UTF-8 boundary panics
    let rest = header
        .strip_prefix("Payment")
        .or_else(|| header.strip_prefix("payment"))
        .or_else(|| header.strip_prefix("PAYMENT"))
        .or_else(|| {
            // Fallback for other case variations
            if header.len() >= 7
                && header
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("Payment"))
            {
                header.get(7..)
            } else {
                None
            }
        })
        .ok_or_else(|| MppError::InvalidChallenge("Expected 'Payment' scheme".to_string()))?;

    // Check for whitespace after scheme
    let params_str = rest
        .strip_prefix(' ')
        .or_else(|| rest.strip_prefix('\t'))
        .ok_or_else(|| {
            MppError::InvalidChallenge("Expected space after 'Payment' scheme".to_string())
        })?
        .trim_start();
    let params = parse_auth_params(params_str);

    // Extract required fields
    let id = params
        .get("id")
        .ok_or_else(|| MppError::InvalidChallenge("Missing 'id' field".to_string()))?
        .clone();

    let realm = params
        .get("realm")
        .ok_or_else(|| MppError::InvalidChallenge("Missing 'realm' field".to_string()))?
        .clone();

    let method_str = params
        .get("method")
        .ok_or_else(|| MppError::InvalidChallenge("Missing 'method' field".to_string()))?;
    let method = MethodName::new(method_str);

    let intent_str = params
        .get("intent")
        .ok_or_else(|| MppError::InvalidChallenge("Missing 'intent' field".to_string()))?;
    let intent = IntentName::new(intent_str);

    let request_b64 = params
        .get("request")
        .ok_or_else(|| MppError::InvalidChallenge("Missing 'request' field".to_string()))?
        .clone();

    // Validate request is valid base64url JSON (but keep raw for echo)
    let _ = base64url_decode(&request_b64)?;
    let request = Base64UrlJson::from_raw(request_b64);

    Ok(PaymentChallenge {
        id,
        realm,
        method,
        intent,
        request,
        expires: params.get("expires").cloned(),
        description: params.get("description").cloned(),
    })
}

/// Parse all WWW-Authenticate headers that use the Payment scheme.
///
/// Returns a Vec of Results - one for each Payment header found.
/// Non-Payment headers are skipped.
///
/// # Examples
///
/// ```
/// use mpay::protocol::core::parse_www_authenticate_all;
///
/// let headers = vec![
///     "Bearer token",
///     "Payment id=\"abc\", realm=\"api\", method=\"tempo\", intent=\"charge\", request=\"e30\"",
///     "Payment id=\"def\", realm=\"api\", method=\"base\", intent=\"charge\", request=\"e30\"",
/// ];
/// let challenges = parse_www_authenticate_all(headers);
/// assert_eq!(challenges.len(), 2);
/// ```
pub fn parse_www_authenticate_all<'a>(
    headers: impl IntoIterator<Item = &'a str>,
) -> Vec<Result<PaymentChallenge>> {
    headers
        .into_iter()
        .filter(|h| {
            h.trim_start()
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("payment "))
        })
        .map(parse_www_authenticate)
        .collect()
}

/// Format a PaymentChallenge as a WWW-Authenticate header value.
///
/// Format: `Payment id="<id>", realm="<realm>", method="<method>", intent="<intent>", request="<base64url-json>"`
///
/// # Examples
///
/// ```
/// use mpay::protocol::core::{PaymentChallenge, format_www_authenticate};
/// use mpay::protocol::core::types::Base64UrlJson;
///
/// let challenge = PaymentChallenge {
///     id: "abc123".to_string(),
///     realm: "api".to_string(),
///     method: "tempo".into(),
///     intent: "charge".into(),
///     request: Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
///     expires: None,
///     description: None,
/// };
/// let header = format_www_authenticate(&challenge).unwrap();
/// assert!(header.starts_with("Payment id=\"abc123\""));
/// ```
pub fn format_www_authenticate(challenge: &PaymentChallenge) -> Result<String> {
    // Escape all quoted values to prevent header injection
    let mut parts = vec![
        format!("id=\"{}\"", escape_quoted_value(&challenge.id)?),
        format!("realm=\"{}\"", escape_quoted_value(&challenge.realm)?),
        format!(
            "method=\"{}\"",
            escape_quoted_value(challenge.method.as_str())?
        ),
        format!(
            "intent=\"{}\"",
            escape_quoted_value(challenge.intent.as_str())?
        ),
        format!(
            "request=\"{}\"",
            escape_quoted_value(challenge.request.raw())?
        ),
    ];

    if let Some(ref expires) = challenge.expires {
        parts.push(format!("expires=\"{}\"", escape_quoted_value(expires)?));
    }

    if let Some(ref description) = challenge.description {
        parts.push(format!(
            "description=\"{}\"",
            escape_quoted_value(description)?
        ));
    }

    Ok(format!("Payment {}", parts.join(", ")))
}

/// Format multiple challenges as WWW-Authenticate header values.
///
/// Per spec, servers can send multiple headers with different payment options.
///
/// # Examples
///
/// ```
/// use mpay::protocol::core::{PaymentChallenge, format_www_authenticate_many};
/// use mpay::protocol::core::types::Base64UrlJson;
///
/// let challenge = PaymentChallenge {
///     id: "abc123".to_string(),
///     realm: "api".to_string(),
///     method: "tempo".into(),
///     intent: "charge".into(),
///     request: Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
///     expires: None,
///     description: None,
/// };
/// let headers = format_www_authenticate_many(&[challenge]).unwrap();
/// assert_eq!(headers.len(), 1);
/// ```
pub fn format_www_authenticate_many(challenges: &[PaymentChallenge]) -> Result<Vec<String>> {
    challenges.iter().map(format_www_authenticate).collect()
}

/// Parse an Authorization header into a PaymentCredential.
///
/// Format: `Payment <base64url-json>`
pub fn parse_authorization(header: &str) -> Result<PaymentCredential> {
    let header = header.trim_start();

    // Case-insensitive scheme matching using strip_prefix to avoid UTF-8 boundary panics
    let rest = header
        .strip_prefix("Payment")
        .or_else(|| header.strip_prefix("payment"))
        .or_else(|| header.strip_prefix("PAYMENT"))
        .or_else(|| {
            // Fallback for other case variations
            if header.len() >= 7
                && header
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("Payment"))
            {
                header.get(7..)
            } else {
                None
            }
        })
        .ok_or_else(|| MppError::InvalidChallenge("Expected 'Payment' scheme".to_string()))?;

    let token = rest.trim();

    // Enforce size limit to prevent memory exhaustion DoS
    if token.len() > MAX_TOKEN_LEN {
        return Err(MppError::InvalidChallenge(format!(
            "Token exceeds maximum length of {} bytes",
            MAX_TOKEN_LEN
        )));
    }

    let decoded = base64url_decode(token)?;
    let credential: PaymentCredential = serde_json::from_slice(&decoded)
        .map_err(|e| MppError::InvalidChallenge(format!("Invalid credential JSON: {}", e)))?;

    Ok(credential)
}

/// Format a PaymentCredential as an Authorization header value.
///
/// Format: `Payment <base64url-json>`
pub fn format_authorization(credential: &PaymentCredential) -> Result<String> {
    let json = serde_json::to_string(credential)?;
    let encoded = base64url_encode(json.as_bytes());
    Ok(format!("Payment {}", encoded))
}

/// Parse a Payment-Receipt header into a PaymentReceipt.
///
/// Format: `<base64url-json>`
pub fn parse_receipt(header: &str) -> Result<PaymentReceipt> {
    let token = header.trim();

    // Enforce size limit to prevent memory exhaustion DoS
    if token.len() > MAX_TOKEN_LEN {
        return Err(MppError::InvalidChallenge(format!(
            "Receipt exceeds maximum length of {} bytes",
            MAX_TOKEN_LEN
        )));
    }

    let decoded = base64url_decode(token)?;
    let receipt: PaymentReceipt = serde_json::from_slice(&decoded)
        .map_err(|e| MppError::InvalidChallenge(format!("Invalid receipt JSON: {}", e)))?;

    Ok(receipt)
}

/// Format a PaymentReceipt as a Payment-Receipt header value.
///
/// Format: `<base64url-json>`
pub fn format_receipt(receipt: &PaymentReceipt) -> Result<String> {
    let json = serde_json::to_string(receipt)?;
    Ok(base64url_encode(json.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::types::{PayloadType, ReceiptStatus};
    use crate::protocol::core::PaymentPayload;

    fn test_challenge() -> PaymentChallenge {
        PaymentChallenge {
            id: "abc123".to_string(),
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "10000",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: Some("2024-01-01T00:00:00Z".to_string()),
            description: None,
        }
    }

    #[test]
    fn test_parse_www_authenticate() {
        let challenge = test_challenge();
        let header = format_www_authenticate(&challenge).unwrap();
        let parsed = parse_www_authenticate(&header).unwrap();

        assert_eq!(parsed.id, "abc123");
        assert_eq!(parsed.realm, "api");
        assert_eq!(parsed.method.as_str(), "tempo");
        assert_eq!(parsed.intent.as_str(), "charge");
        assert_eq!(parsed.expires, Some("2024-01-01T00:00:00Z".to_string()));

        // Verify request decodes correctly
        let request: serde_json::Value = parsed.request.decode_value().unwrap();
        assert_eq!(request["amount"], "10000");
    }

    #[test]
    fn test_parse_www_authenticate_case_insensitive() {
        let header =
            r#"payment id="test", realm="api", method="tempo", intent="charge", request="e30""#;
        let parsed = parse_www_authenticate(header).unwrap();
        assert_eq!(parsed.id, "test");

        let header2 =
            r#"PAYMENT id="test2", realm="api", method="tempo", intent="charge", request="e30""#;
        let parsed2 = parse_www_authenticate(header2).unwrap();
        assert_eq!(parsed2.id, "test2");
    }

    #[test]
    fn test_parse_www_authenticate_leading_whitespace() {
        let header =
            r#"  Payment id="test", realm="api", method="tempo", intent="charge", request="e30""#;
        let parsed = parse_www_authenticate(header).unwrap();
        assert_eq!(parsed.id, "test");
    }

    #[test]
    fn test_parse_www_authenticate_with_description() {
        let mut challenge = test_challenge();
        challenge.description = Some("Pay \"here\" now".to_string());
        let header = format_www_authenticate(&challenge).unwrap();

        assert!(header.contains("description=\"Pay \\\"here\\\" now\""));

        let parsed = parse_www_authenticate(&header).unwrap();
        assert_eq!(parsed.description, Some("Pay \"here\" now".to_string()));
    }

    #[test]
    fn test_parse_www_authenticate_all() {
        let headers = vec![
            "Bearer token",
            r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30""#,
            "Basic xyz",
            r#"Payment id="b", realm="api", method="base", intent="charge", request="e30""#,
        ];

        let results = parse_www_authenticate_all(headers);
        assert_eq!(results.len(), 2);

        let first = results[0].as_ref().unwrap();
        assert_eq!(first.id, "a");

        let second = results[1].as_ref().unwrap();
        assert_eq!(second.id, "b");
    }

    #[test]
    fn test_format_www_authenticate_many() {
        let c1 = test_challenge();
        let mut c2 = test_challenge();
        c2.id = "def456".to_string();
        c2.method = "base".into();

        let headers = format_www_authenticate_many(&[c1, c2]).unwrap();
        assert_eq!(headers.len(), 2);
        assert!(headers[0].contains("abc123"));
        assert!(headers[1].contains("def456"));
    }

    #[test]
    fn test_parse_authorization() {
        let challenge = test_challenge();
        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:42431:0x123",
            PaymentPayload::transaction("0xabc"),
        );

        let header = format_authorization(&credential).unwrap();
        let parsed = parse_authorization(&header).unwrap();

        assert_eq!(parsed.challenge.id, "abc123");
        assert_eq!(
            parsed.source,
            Some("did:pkh:eip155:42431:0x123".to_string())
        );
        assert_eq!(parsed.payload.signature(), Some("0xabc"));
        assert_eq!(parsed.payload.payload_type(), PayloadType::Transaction);
    }

    #[test]
    fn test_parse_receipt() {
        let receipt = PaymentReceipt {
            status: ReceiptStatus::Success,
            method: "tempo".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "0xabc123".to_string(),
        };

        let header = format_receipt(&receipt).unwrap();
        let parsed = parse_receipt(&header).unwrap();

        assert_eq!(parsed.status, ReceiptStatus::Success);
        assert_eq!(parsed.method.as_str(), "tempo");
        assert_eq!(parsed.reference, "0xabc123");
    }

    #[test]
    fn test_parse_invalid_scheme() {
        let result = parse_www_authenticate("Basic realm=\"test\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_required_field() {
        let result = parse_www_authenticate("Payment id=\"abc\", realm=\"api\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip_preserves_request() {
        let original_request = serde_json::json!({
            "amount": "5000",
            "currency": "0xabc",
            "nested": {"key": "value"}
        });
        let mut challenge = test_challenge();
        challenge.request = Base64UrlJson::from_value(&original_request).unwrap();

        let header = format_www_authenticate(&challenge).unwrap();
        let parsed = parse_www_authenticate(&header).unwrap();

        // The raw b64 should be preserved exactly
        assert_eq!(parsed.request.raw(), challenge.request.raw());

        // And should decode to the same value
        let decoded: serde_json::Value = parsed.request.decode_value().unwrap();
        assert_eq!(decoded, original_request);
    }
}
