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

use super::challenge::{PaymentChallenge, PaymentCredential, Receipt};
use super::types::{base64url_decode, base64url_encode, Base64UrlJson, IntentName, MethodName};
use crate::error::{MppError, Result};
use std::collections::HashMap;

/// Maximum length for base64url-encoded tokens to prevent memory exhaustion DoS.
const MAX_TOKEN_LEN: usize = 16 * 1024;

/// Macro to extract a required parameter from the params map.
macro_rules! require_param {
    ($params:expr, $key:literal) => {
        $params.get($key).ok_or_else(|| {
            MppError::invalid_challenge_reason(format!("Missing '{}' field", $key))
        })?
    };
}

/// Strip the Payment scheme prefix (case-insensitive) from a header value.
/// Returns the remainder of the header after the scheme, or None if not a Payment header.
fn strip_payment_scheme(header: &str) -> Option<&str> {
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

/// Extract the `Payment` scheme from an Authorization header that may contain
/// multiple comma-separated schemes (per RFC 9110).
///
/// Returns the `Payment ...` scheme string, or `None` if not found.
/// This matches the TypeScript SDK's `Credential.extractPaymentScheme`.
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::extract_payment_scheme;
///
/// // Single Payment scheme
/// assert!(extract_payment_scheme("Payment eyJhYmMi...").is_some());
///
/// // Mixed schemes (comma-separated per RFC 9110)
/// let header = "Bearer token123, Payment eyJhYmMi...";
/// let payment = extract_payment_scheme(header).unwrap();
/// assert!(payment.starts_with("Payment "));
///
/// // No Payment scheme
/// assert!(extract_payment_scheme("Bearer token123").is_none());
/// ```
pub fn extract_payment_scheme(header: &str) -> Option<&str> {
    header.split(',').map(|s| s.trim()).find(|s| {
        s.len() >= 8
            && s.get(..8)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("payment "))
    })
}

/// Escape a string for use in a quoted-string header value.
/// Rejects CRLF to prevent header injection attacks.
fn escape_quoted_value(s: &str) -> Result<String> {
    if s.contains('\r') || s.contains('\n') {
        return Err(MppError::invalid_challenge_reason(
            "Header value contains invalid CRLF characters",
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
fn parse_auth_params(params_str: &str) -> Result<HashMap<String, String>> {
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

        if params.contains_key(&key) {
            return Err(MppError::invalid_challenge_reason(format!(
                "Duplicate parameter: {}",
                key
            )));
        }
        params.insert(key, value);
    }

    Ok(params)
}

/// Validate ISO 8601 / RFC 3339 timestamp format.
fn is_iso8601_timestamp(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok()
}

/// Validate digest format.
///
/// Matches TypeScript SDK behavior: digest must start with `sha-256=`.
fn is_valid_digest_format(d: &str) -> bool {
    d.starts_with("sha-256=")
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
/// use mpp::protocol::core::parse_www_authenticate;
///
/// let header = r#"Payment id="abc123", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwMCJ9""#;
/// let challenge = parse_www_authenticate(header).unwrap();
/// assert_eq!(challenge.id, "abc123");
/// ```
pub fn parse_www_authenticate(header: &str) -> Result<PaymentChallenge> {
    let rest = strip_payment_scheme(header).ok_or_else(|| {
        MppError::invalid_challenge_reason("Expected 'Payment' scheme".to_string())
    })?;

    let params_str = rest
        .strip_prefix(' ')
        .or_else(|| rest.strip_prefix('\t'))
        .ok_or_else(|| {
            MppError::invalid_challenge_reason("Expected space after 'Payment' scheme".to_string())
        })?
        .trim_start();
    let params = parse_auth_params(params_str)?;

    let id = require_param!(params, "id").clone();
    if id.is_empty() {
        return Err(MppError::invalid_challenge_reason(
            "Empty 'id' parameter".to_string(),
        ));
    }
    let realm = require_param!(params, "realm").clone();
    let method_raw = require_param!(params, "method").clone();
    if method_raw.is_empty() || !method_raw.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(MppError::invalid_challenge_reason(format!(
            "Invalid method: \"{}\". Must match method-name ABNF.",
            method_raw
        )));
    }
    let method = MethodName::new(method_raw);
    let intent = IntentName::new(require_param!(params, "intent"));
    let request_b64 = require_param!(params, "request").clone();

    let request_bytes = base64url_decode(&request_b64)?;
    // Validate that the decoded bytes are valid JSON (matches TS SDK behavior)
    let _ = serde_json::from_slice::<serde_json::Value>(&request_bytes).map_err(|e| {
        MppError::invalid_challenge_reason(format!("Invalid JSON in request field: {}", e))
    })?;
    let request = Base64UrlJson::from_raw(request_b64);

    let digest = params.get("digest").cloned();
    if let Some(ref d) = digest {
        if !is_valid_digest_format(d) {
            return Err(MppError::invalid_challenge_reason("Invalid digest format"));
        }
    }

    Ok(PaymentChallenge {
        id,
        realm,
        method,
        intent,
        request,
        expires: params.get("expires").cloned(),
        description: params.get("description").cloned(),
        digest,
        opaque: params.get("opaque").map(Base64UrlJson::from_raw),
    })
}

/// Parse all Payment challenges from one or more WWW-Authenticate header values.
///
/// Handles both:
/// - Multiple separate header values (one challenge each)
/// - A single header value containing multiple comma-separated Payment challenges
///   (per RFC 9110 §11.6.1)
///
/// Returns a Vec of Results - one for each Payment challenge found.
/// Non-Payment headers are skipped.
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::parse_www_authenticate_all;
///
/// // Separate header values
/// let headers = vec![
///     "Bearer token",
///     "Payment id=\"abc\", realm=\"api\", method=\"tempo\", intent=\"charge\", request=\"e30\"",
///     "Payment id=\"def\", realm=\"api\", method=\"base\", intent=\"charge\", request=\"e30\"",
/// ];
/// let challenges = parse_www_authenticate_all(headers);
/// assert_eq!(challenges.len(), 2);
/// ```
///
/// ```
/// use mpp::protocol::core::parse_www_authenticate_all;
///
/// // Single header with multiple challenges
/// let header = concat!(
///     r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30", "#,
///     r#"Payment id="b", realm="api", method="stripe", intent="charge", request="e30""#,
/// );
/// let challenges = parse_www_authenticate_all(vec![header]);
/// assert_eq!(challenges.len(), 2);
/// ```
pub fn parse_www_authenticate_all<'a>(
    headers: impl IntoIterator<Item = &'a str>,
) -> Vec<Result<PaymentChallenge>> {
    headers
        .into_iter()
        .flat_map(split_payment_challenges)
        .map(parse_www_authenticate)
        .collect()
}

/// Split a header value into individual `Payment` challenge slices.
///
/// Finds `Payment ` scheme boundaries (case-insensitive per RFC 9110 §11.6.1)
/// that appear at the start of the header or after a comma separator, and
/// returns the individual challenge strings.
fn split_payment_challenges(header: &str) -> Vec<&str> {
    fn is_valid_start(header: &str, pos: usize) -> bool {
        pos == 0 || header[..pos].bytes().rfind(|b| !b.is_ascii_whitespace()) == Some(b',')
    }

    let lower = header.to_ascii_lowercase();

    let starts: Vec<_> = lower
        .match_indices("payment ")
        .map(|(pos, _)| pos)
        .filter(|&pos| is_valid_start(header, pos))
        .collect();

    starts
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let end = starts.get(i + 1).copied().unwrap_or(header.len());
            header[start..end].trim_end_matches([',', ' '])
        })
        .collect()
}

/// Format a PaymentChallenge as a WWW-Authenticate header value.
///
/// Format: `Payment id="<id>", realm="<realm>", method="<method>", intent="<intent>", request="<base64url-json>"`
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::{PaymentChallenge, format_www_authenticate};
/// use mpp::protocol::core::types::Base64UrlJson;
///
/// let challenge = PaymentChallenge {
///     id: "abc123".to_string(),
///     realm: "api".to_string(),
///     method: "tempo".into(),
///     intent: "charge".into(),
///     request: Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
///     expires: None,
///     description: None,
///     digest: None,
///     opaque: None,
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

    if let Some(ref digest) = challenge.digest {
        parts.push(format!("digest=\"{}\"", escape_quoted_value(digest)?));
    }

    if let Some(ref opaque) = challenge.opaque {
        parts.push(format!("opaque=\"{}\"", escape_quoted_value(opaque.raw())?));
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
/// use mpp::protocol::core::{PaymentChallenge, format_www_authenticate_many};
/// use mpp::protocol::core::types::Base64UrlJson;
///
/// let challenge = PaymentChallenge {
///     id: "abc123".to_string(),
///     realm: "api".to_string(),
///     method: "tempo".into(),
///     intent: "charge".into(),
///     request: Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
///     expires: None,
///     description: None,
///     digest: None,
///     opaque: None,
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
    let payment_part = extract_payment_scheme(header).ok_or_else(|| {
        MppError::invalid_challenge_reason("Expected 'Payment' scheme".to_string())
    })?;

    // Strip "Payment " prefix to get the token
    let token = payment_part.get(8..).unwrap_or("").trim();

    // Enforce size limit to prevent memory exhaustion DoS
    if token.len() > MAX_TOKEN_LEN {
        return Err(MppError::invalid_challenge_reason(format!(
            "Token exceeds maximum length of {} bytes",
            MAX_TOKEN_LEN
        )));
    }

    let decoded = base64url_decode(token)?;
    let credential: PaymentCredential = serde_json::from_slice(&decoded).map_err(|e| {
        MppError::invalid_challenge_reason(format!("Invalid credential JSON: {}", e))
    })?;

    if let Some(ref d) = credential.challenge.digest {
        if !is_valid_digest_format(d) {
            return Err(MppError::invalid_challenge_reason("Invalid digest format"));
        }
    }

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

/// Parse a Payment-Receipt header into a Receipt.
///
/// Format: `<base64url-json>`
pub fn parse_receipt(header: &str) -> Result<Receipt> {
    let token = header.trim();

    // Enforce size limit to prevent memory exhaustion DoS
    if token.len() > MAX_TOKEN_LEN {
        return Err(MppError::invalid_challenge_reason(format!(
            "Receipt exceeds maximum length of {} bytes",
            MAX_TOKEN_LEN
        )));
    }

    let decoded = base64url_decode(token)?;
    let receipt: Receipt = serde_json::from_slice(&decoded)
        .map_err(|e| MppError::invalid_challenge_reason(format!("Invalid receipt JSON: {}", e)))?;

    if !is_iso8601_timestamp(&receipt.timestamp) {
        return Err(MppError::invalid_challenge_reason(
            "Invalid timestamp format: expected ISO 8601".to_string(),
        ));
    }

    Ok(receipt)
}

/// Format a Receipt as a Payment-Receipt header value.
///
/// Format: `<base64url-json>`
pub fn format_receipt(receipt: &Receipt) -> Result<String> {
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
            digest: None,
            opaque: None,
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
        let charge_payload: PaymentPayload = parsed.charge_payload().unwrap();
        assert_eq!(charge_payload.signed_tx(), Some("0xabc"));
        assert_eq!(charge_payload.payload_type(), PayloadType::Transaction);
    }

    #[test]
    fn test_parse_receipt() {
        let receipt = Receipt {
            status: ReceiptStatus::Success,
            method: "tempo".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "0xabc123".to_string(),
            external_id: None,
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
    fn test_parse_authorization_missing_payment_scheme() {
        let result = parse_authorization("Bearer abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_authorization_invalid_base64url() {
        let result = parse_authorization("Payment !");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_authorization_invalid_json() {
        let token = base64url_encode(b"not valid json");
        let result = parse_authorization(&format!("Payment {}", token));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_authorization_missing_challenge_fields() {
        let json = r#"{"challenge":{"id":"abc"},"payload":{}}"#;
        let token = base64url_encode(json.as_bytes());
        let result = parse_authorization(&format!("Payment {}", token));
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_roundtrip_with_optional_fields() {
        let mut challenge = test_challenge();
        challenge.expires = Some("2025-06-01T00:00:00Z".to_string());
        challenge.digest = Some("sha-256=abc123".to_string());

        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:42431:0x123",
            PaymentPayload::transaction("0xabc"),
        );

        let header = format_authorization(&credential).unwrap();
        let parsed = parse_authorization(&header).unwrap();

        assert_eq!(
            parsed.challenge.expires,
            Some("2025-06-01T00:00:00Z".to_string())
        );
        assert_eq!(parsed.challenge.digest, Some("sha-256=abc123".to_string()));
    }

    #[test]
    fn test_credential_roundtrip_without_source() {
        let challenge = test_challenge();
        let credential =
            PaymentCredential::new(challenge.to_echo(), PaymentPayload::transaction("0xabc"));

        let header = format_authorization(&credential).unwrap();
        let parsed = parse_authorization(&header).unwrap();

        assert!(parsed.source.is_none());
    }

    #[test]
    fn test_parse_receipt_invalid_status() {
        let json = r#"{"status":"failed","method":"tempo","timestamp":"2024-01-01T00:00:00Z","reference":"0xabc"}"#;
        let token = base64url_encode(json.as_bytes());
        let result = parse_receipt(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_authorization_invalid_digest_format() {
        let mut challenge = test_challenge();
        challenge.digest = Some("invalid-digest-format".to_string());

        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:42431:0x123",
            PaymentPayload::transaction("0xabc"),
        );

        // Manually serialize with the invalid digest intact
        let json = serde_json::to_string(&credential).unwrap();
        let token = base64url_encode(json.as_bytes());
        let result = parse_authorization(&format!("Payment {}", token));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_authorization_rejects_non_sha256_digest() {
        let mut challenge = test_challenge();
        challenge.digest = Some("sha-512=abc123".to_string());

        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:42431:0x123",
            PaymentPayload::transaction("0xabc"),
        );

        let json = serde_json::to_string(&credential).unwrap();
        let token = base64url_encode(json.as_bytes());
        let result = parse_authorization(&format!("Payment {}", token));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_www_authenticate_invalid_digest_format() {
        let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="e30", digest="invalid-digest-format""#;
        let result = parse_www_authenticate(header);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_www_authenticate_rejects_non_sha256_digest() {
        let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="e30", digest="sha-512=abc""#;
        let result = parse_www_authenticate(header);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_www_authenticate_invalid_request_json() {
        // "not json" base64url-encoded is "bm90IGpzb24"
        let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="bm90IGpzb24""#;
        let result = parse_www_authenticate(header);
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

    #[test]
    fn test_extract_payment_scheme_single() {
        let header = "Payment eyJhYmMi";
        let result = extract_payment_scheme(header);
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("Payment "));
    }

    #[test]
    fn test_extract_payment_scheme_mixed() {
        let header = "Bearer token123, Payment eyJhYmMi";
        let result = extract_payment_scheme(header);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Payment eyJhYmMi");
    }

    #[test]
    fn test_extract_payment_scheme_not_found() {
        assert!(extract_payment_scheme("Bearer token123").is_none());
        assert!(extract_payment_scheme("Basic abc123").is_none());
    }

    #[test]
    fn test_extract_payment_scheme_case_insensitive() {
        let header = "Bearer xxx, payment eyJhYmMi";
        let result = extract_payment_scheme(header);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_authorization_mixed_schemes() {
        let challenge = test_challenge();
        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:42431:0x123",
            PaymentPayload::transaction("0xabc"),
        );
        let formatted = format_authorization(&credential).unwrap();

        // Prepend a Bearer scheme to simulate mixed Authorization
        let mixed = format!("Bearer some-token, {}", formatted);
        let parsed = parse_authorization(&mixed).unwrap();
        assert_eq!(parsed.challenge.id, "abc123");
    }

    #[test]
    fn test_parse_www_authenticate_rejects_duplicate_params() {
        let header = r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30", id="b""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Duplicate parameter"));
    }

    #[test]
    fn test_parse_www_authenticate_rejects_empty_id() {
        let header =
            r#"Payment id="", realm="api", method="tempo", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Empty 'id'"));
    }

    #[test]
    fn test_parse_www_authenticate_rejects_invalid_method_name_dash() {
        let header =
            r#"Payment id="abc", realm="api", method="tempo-v2", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Invalid method"));
    }

    #[test]
    fn test_parse_www_authenticate_rejects_invalid_method_name_digit_prefix() {
        let header =
            r#"Payment id="abc", realm="api", method="1tempo", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Invalid method"));
    }

    #[test]
    fn test_parse_www_authenticate_rejects_mixed_case_method_name() {
        let header =
            r#"Payment id="abc", realm="api", method="Tempo", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Invalid method"));
    }

    #[test]
    fn test_parse_www_authenticate_accepts_standard_base64_request() {
        // Reproduces real-world interop issue: server sends the `request`
        // field as standard base64 ('+', '/', '=' padding) instead of
        // base64url (no padding). The parser should accept both variants,
        // matching the mppx TypeScript SDK behavior.
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let payload = r#"{"amount":"94","currency":"0x20c000000000000000000000b9537d11c60e8b50","methodDetails":{"chainId":4217},"recipient":"0x8A739f3A6f40194C0128904bC387e63d9C0577A4"}"#;
        let request_b64 = STANDARD.encode(payload.as_bytes());
        // Verify it has padding
        assert!(request_b64.ends_with('='));

        let header = format!(
            r#"Payment id="test-123", realm="mpp-hosting", method="tempo", intent="charge", request="{request_b64}", description="VPS provisioning", expires="2026-03-24T21:20:34Z""#,
        );
        let challenge = parse_www_authenticate(&header).unwrap();
        assert_eq!(challenge.id, "test-123");
        assert_eq!(challenge.method.to_string(), "tempo");
        assert_eq!(challenge.intent.to_string(), "charge");

        let decoded: serde_json::Value = challenge.request.decode().unwrap();
        assert_eq!(decoded["amount"], "94");
    }

    #[test]
    fn test_parse_receipt_rejects_non_iso8601_timestamp() {
        // {"method":"tempo","reference":"0xabc","status":"success","timestamp":"Jan 29 2026 12:00"}
        // base64url encoded
        let wire = "eyJtZXRob2QiOiJ0ZW1wbyIsInJlZmVyZW5jZSI6IjB4YWJjIiwic3RhdHVzIjoic3VjY2VzcyIsInRpbWVzdGFtcCI6IkphbiAyOSAyMDI2IDEyOjAwIn0";
        let err = parse_receipt(wire).unwrap_err();
        assert!(err.to_string().contains("timestamp"));
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

    #[test]
    fn test_parse_www_authenticate_all_multi_challenge() {
        let header = concat!(
            r#"Payment id="t1", realm="api", method="tempo", intent="charge", request="e30", "#,
            r#"Payment id="s1", realm="api", method="stripe", intent="charge", request="e30""#,
        );
        let results = parse_www_authenticate_all(vec![header]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().method.as_str(), "tempo");
        assert_eq!(results[1].as_ref().unwrap().method.as_str(), "stripe");
    }

    #[test]
    fn test_parse_www_authenticate_all_ignores_non_payment_schemes() {
        // Bearer and other non-Payment schemes should be silently ignored
        let headers = vec![
            "Bearer token123",
            r#"Payment id="t1", realm="api", method="tempo", intent="charge", request="e30""#,
            "Basic dXNlcjpwYXNz",
        ];
        let results = parse_www_authenticate_all(headers);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_ref().unwrap().method.as_str(), "tempo");

        // Mixed in a single header value: Bearer prefix followed by Payment challenge
        let mixed = concat!(
            "Bearer token123, ",
            r#"Payment id="s1", realm="api", method="stripe", intent="charge", request="e30""#,
        );
        let results = parse_www_authenticate_all(vec![mixed]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_ref().unwrap().method.as_str(), "stripe");
    }
}
