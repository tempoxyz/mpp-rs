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

use super::auth_params::{
    escape_quoted_value, parse_auth_params, split_payment_challenges, starts_with_payment_scheme,
    strip_payment_scheme,
};
use super::challenge::PaymentChallenge;
use super::credential::PaymentCredential;
use super::receipt::Receipt;
use super::types::{base64url_decode, base64url_encode, Base64UrlJson, IntentName, MethodName};
use crate::error::{MppError, Result};
use std::borrow::Cow;

/// Maximum length for base64url-encoded tokens to prevent memory exhaustion DoS.
pub(super) const MAX_TOKEN_LEN: usize = 16 * 1024;

/// Macro to extract a required parameter from the params map.
macro_rules! require_param {
    ($params:expr, $key:literal) => {
        $params.get($key).ok_or_else(|| {
            MppError::invalid_challenge_reason(format!("Missing '{}' field", $key))
        })?
    };
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
    header
        .split(',')
        .map(|s| s.trim())
        .find(|s| starts_with_payment_scheme(s.as_bytes()))
}

/// Header name for payment challenges (from server)
pub const WWW_AUTHENTICATE_HEADER: &str = "www-authenticate";

/// Header name for payment credentials (from client)
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// Alternate header name for payment credentials when `Authorization` is
/// reserved for ordinary application authentication.
pub const PAYMENT_AUTHORIZATION_HEADER: &str = "Payment-Authorization";

/// Header name for payment receipts (from server)
pub const PAYMENT_RECEIPT_HEADER: &str = "payment-receipt";

/// Scheme identifier for the Payment authentication scheme
pub const PAYMENT_SCHEME: &str = "Payment";

/// Merge a `private` directive into an existing `Cache-Control` value.
///
/// Receipt responses MUST be `Cache-Control: private` (draft-httpauth-payment-00
/// §11.10). Empty/none → `"private"`; already-private → unchanged; otherwise
/// `, private` is appended, preserving other directives. Mirrors mppx.
pub fn with_private_cache_control(value: Option<&str>) -> String {
    match value {
        Some(v) if !v.trim().is_empty() => {
            let has_private = v
                .split(',')
                .any(|directive| directive.trim().eq_ignore_ascii_case("private"));
            if has_private {
                v.to_string()
            } else {
                format!("{v}, private")
            }
        }
        _ => "private".to_string(),
    }
}

/// Validate ISO 8601 / RFC 3339 timestamp format.
fn is_iso8601_timestamp(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok()
}

/// Validate digest format: `sha-256=` followed by the base64 hash, either bare
/// (as mppx emits it) or as an RFC 9530 byte sequence (`:<base64>:`).
fn is_valid_digest_format(d: &str) -> bool {
    let Some(value) = d.strip_prefix("sha-256=") else {
        return false;
    };
    let value = value
        .strip_prefix(':')
        .and_then(|value| value.strip_suffix(':'))
        .unwrap_or(value);
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
        })
}

/// Validate an intent name: the spec grammar `1*( ALPHA / DIGIT / "-" )`,
/// plus `_`, which mppx accepts in custom intents.
fn is_valid_intent_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Validate the method identifier grammar used by mppx.
fn is_valid_method_name(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && chars.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, ':' | '_' | '-')
        })
}

/// Validate that a `request` parameter is a base64url-encoded JSON object.
fn validate_request(request_b64: &str) -> Result<()> {
    let request_bytes = base64url_decode(request_b64)?;
    // Validate that the decoded bytes are a JSON object (matches TS SDK behavior)
    serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&request_bytes).map_err(
        |e| MppError::invalid_challenge_reason(format!("Invalid JSON in request field: {}", e)),
    )?;
    Ok(())
}

/// Validate the wire form of a challenge's `id` and of the fields the id binds.
///
/// The id is an HMAC over the bound fields joined with `|`, so none of them
/// may contain one. This is the single validator for challenges parsed from
/// `WWW-Authenticate`, deserialized from JSON, and echoed in a credential.
pub(super) fn validate_challenge_fields(
    id: &str,
    intent: &str,
    request: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
) -> Result<()> {
    if id.is_empty() {
        return Err(MppError::invalid_challenge_reason(
            "Empty 'id' parameter".to_string(),
        ));
    }
    if !is_valid_intent_name(intent) {
        return Err(MppError::invalid_challenge_reason(format!(
            "Invalid intent: \"{}\".",
            intent
        )));
    }
    validate_request(request)?;
    if digest.is_some_and(|digest| !is_valid_digest_format(digest)) {
        return Err(MppError::invalid_challenge_reason("Invalid digest format"));
    }
    if expires.is_some_and(|expires| !is_iso8601_timestamp(expires)) {
        return Err(MppError::invalid_challenge_reason(
            "Invalid expires timestamp",
        ));
    }
    if opaque.is_some_and(|opaque| base64url_decode(opaque).is_err()) {
        return Err(MppError::invalid_challenge_reason(
            "Invalid opaque: expected base64url",
        ));
    }
    Ok(())
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
    let realm = require_param!(params, "realm").clone();
    let method_raw = require_param!(params, "method").clone();
    if !is_valid_method_name(&method_raw) {
        return Err(MppError::invalid_challenge_reason(format!(
            "Invalid method: \"{}\". Must match method-name ABNF.",
            method_raw
        )));
    }
    let method = MethodName::new(method_raw);
    let intent = IntentName::from_wire(require_param!(params, "intent"));
    let request = Base64UrlJson::from_raw(require_param!(params, "request"));
    let digest = params.get("digest").cloned();
    let expires = params.get("expires").cloned();
    let opaque = params.get("opaque").map(Base64UrlJson::from_raw);

    validate_challenge_fields(
        &id,
        intent.as_str(),
        request.raw(),
        expires.as_deref(),
        digest.as_deref(),
        opaque.as_ref().map(Base64UrlJson::raw),
    )?;

    Ok(PaymentChallenge {
        id,
        realm,
        method,
        intent,
        request,
        expires,
        description: params.get("description").cloned(),
        digest,
        opaque,
        header: super::parse_advertised_credential_header(
            params.get("header").map(String::as_str),
        )?,
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
///
/// // Merged into a single header value
/// let merged = vec![
///     "Payment id=\"abc\", realm=\"api\", method=\"tempo\", intent=\"charge\", request=\"e30\", Payment id=\"def\", realm=\"api\", method=\"base\", intent=\"charge\", request=\"e30\"",
/// ];
/// let challenges = parse_www_authenticate_all(merged);
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

/// Parse all Payment challenges from raw `WWW-Authenticate` field values.
///
/// Like [`parse_www_authenticate_all`], but takes the field values as the
/// bytes received on the wire and decodes them as ISO-8859-1 (RFC 9110 §5.5).
/// Servers that send Latin-1 text in a quoted-string as single raw bytes, as
/// mppx does, are not readable as ASCII or UTF-8.
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::parse_www_authenticate_all_bytes;
///
/// let header: &[u8] =
///     b"Payment id=\"abc\", realm=\"caf\xe9\", method=\"tempo\", intent=\"charge\", request=\"e30\"";
/// let challenges = parse_www_authenticate_all_bytes([header]);
/// assert_eq!(challenges[0].as_ref().unwrap().realm, "caf\u{e9}");
/// ```
pub fn parse_www_authenticate_all_bytes<'a>(
    headers: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<Result<PaymentChallenge>> {
    headers
        .into_iter()
        .flat_map(|value| {
            let value = decode_latin1(value);
            split_payment_challenges(&value)
                .into_iter()
                .map(parse_www_authenticate)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn decode_latin1(value: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(value) {
        Ok(ascii) if ascii.is_ascii() => Cow::Borrowed(ascii),
        _ => Cow::Owned(value.iter().copied().map(char::from).collect()),
    }
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
///     header: None,
/// };
/// let header = format_www_authenticate(&challenge).unwrap();
/// assert!(header.starts_with("Payment id=\"abc123\""));
/// ```
///
/// # Errors
///
/// Returns an error for challenges that [`parse_www_authenticate`] would
/// reject: an empty `id`, an invalid method or intent name, a `request` that
/// is not a base64url-encoded JSON object, or a malformed `expires`, `digest`
/// or `opaque`. Quoted values containing CR or LF are rejected too.
pub fn format_www_authenticate(challenge: &PaymentChallenge) -> Result<String> {
    if !is_valid_method_name(challenge.method.as_str()) {
        return Err(MppError::invalid_challenge_reason(format!(
            "Invalid method: \"{}\". Must match method-name ABNF.",
            challenge.method
        )));
    }
    validate_challenge_fields(
        &challenge.id,
        challenge.intent.as_str(),
        challenge.request.raw(),
        challenge.expires.as_deref(),
        challenge.digest.as_deref(),
        challenge.opaque.as_ref().map(Base64UrlJson::raw),
    )?;

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

    if let Some(header) = super::parse_advertised_credential_header(challenge.header.as_deref())? {
        parts.push(format!("header=\"{}\"", escape_quoted_value(&header)?));
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
///     header: None,
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
    let payment_part = extract_payment_scheme(header)
        .ok_or_else(|| MppError::malformed_credential("Expected 'Payment' scheme"))?;

    // Strip "Payment " prefix to get the token
    let token = payment_part.get(8..).unwrap_or("").trim();

    // Enforce size limit to prevent memory exhaustion DoS
    if token.len() > MAX_TOKEN_LEN {
        return Err(MppError::malformed_credential(format!(
            "Token exceeds maximum length of {} bytes",
            MAX_TOKEN_LEN
        )));
    }

    let decoded =
        base64url_decode(token).map_err(|_| MppError::malformed_credential("Invalid base64url"))?;
    let mut credential: PaymentCredential = serde_json::from_slice(&decoded)
        .map_err(|e| MppError::malformed_credential(format!("Invalid credential JSON: {}", e)))?;

    credential.challenge.header = super::parse_advertised_credential_header(
        credential.challenge.header.as_deref(),
    )
    .map_err(|_| {
        MppError::malformed_credential(
            "Unsupported credential header: must be Payment-Authorization",
        )
    })?;

    let echo = &credential.challenge;
    validate_challenge_fields(
        &echo.id,
        echo.intent.as_str(),
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(Base64UrlJson::raw),
    )
    .map_err(|error| match error {
        MppError::InvalidChallenge {
            reason: Some(reason),
            ..
        } => MppError::malformed_credential(reason),
        error => MppError::malformed_credential(error.to_string()),
    })?;

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
        return Err(MppError::InvalidReceipt(format!(
            "Receipt exceeds maximum length of {} bytes",
            MAX_TOKEN_LEN
        )));
    }

    let decoded = base64url_decode(token)?;
    let receipt: Receipt = serde_json::from_slice(&decoded)
        .map_err(|e| MppError::InvalidReceipt(format!("Invalid receipt JSON: {}", e)))?;

    if !is_iso8601_timestamp(&receipt.timestamp) {
        return Err(MppError::InvalidReceipt(
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
    use crate::protocol::core::challenge::tests::test_challenge;
    use crate::protocol::core::types::{PayloadType, ReceiptStatus};
    use crate::protocol::core::PaymentPayload;

    #[test]
    fn test_with_private_cache_control() {
        // No existing value → "private".
        assert_eq!(with_private_cache_control(None), "private");
        // Empty / whitespace-only existing value → "private".
        assert_eq!(with_private_cache_control(Some("")), "private");
        assert_eq!(with_private_cache_control(Some("   ")), "private");
        // Other directives preserved, `private` appended.
        assert_eq!(
            with_private_cache_control(Some("no-store")),
            "no-store, private"
        );
        assert_eq!(
            with_private_cache_control(Some("public, max-age=60")),
            "public, max-age=60, private"
        );
        // Already private → returned unchanged (no duplicate).
        assert_eq!(with_private_cache_control(Some("private")), "private");
        assert_eq!(
            with_private_cache_control(Some("private, max-age=0")),
            "private, max-age=0"
        );
        // Detection is case-insensitive and whitespace-tolerant.
        assert_eq!(with_private_cache_control(Some("  PRIVATE ")), "  PRIVATE ");
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
    fn test_parse_www_authenticate_rejects_invalid_expires_timestamp() {
        let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="e30", expires="not-a-date""#;

        let err = parse_www_authenticate(header).unwrap_err();

        assert!(err.to_string().contains("Invalid expires timestamp"));
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
    fn test_parse_www_authenticate_rejects_unterminated_quoted_string() {
        let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="e30", description="oops"#;

        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Unterminated quoted-string"));
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
    fn test_parse_www_authenticate_all_merged() {
        // Two Payment schemes in a single comma-separated header value
        let merged = r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30", Payment id="b", realm="api", method="stripe", intent="charge", request="e30""#;
        let results = parse_www_authenticate_all(vec![merged]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().id, "a");
        assert_eq!(results[0].as_ref().unwrap().method.as_str(), "tempo");
        assert_eq!(results[1].as_ref().unwrap().id, "b");
        assert_eq!(results[1].as_ref().unwrap().method.as_str(), "stripe");
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
            subscription_id: None,
            extensions: serde_json::Map::new(),
        };

        let header = format_receipt(&receipt).unwrap();
        let parsed = parse_receipt(&header).unwrap();

        assert_eq!(parsed.status, ReceiptStatus::Success);
        assert_eq!(parsed.method.as_str(), "tempo");
        assert_eq!(parsed.reference, "0xabc123");
    }

    #[test]
    fn test_receipt_subscription_id_round_trip() {
        let receipt = Receipt {
            status: ReceiptStatus::Success,
            method: "tempo".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "0xabc123".to_string(),
            external_id: None,
            subscription_id: Some("sub_123".to_string()),
            extensions: serde_json::Map::new(),
        };

        let header = format_receipt(&receipt).unwrap();
        let parsed = parse_receipt(&header).unwrap();

        assert_eq!(parsed.subscription_id.as_deref(), Some("sub_123"));
    }

    #[test]
    fn test_parse_receipt_preserves_foreign_subscription_id() {
        // A receipt produced by a non-Rust SDK (e.g. mppx) carrying subscriptionId
        // must survive parsing rather than being silently dropped.
        let json = r#"{"status":"success","method":"tempo","timestamp":"2024-01-01T00:00:00Z","reference":"0xabc123","subscriptionId":"sub_123"}"#;
        let header = base64url_encode(json.as_bytes());

        let parsed = parse_receipt(&header).unwrap();

        assert_eq!(parsed.subscription_id.as_deref(), Some("sub_123"));
    }

    #[test]
    fn test_receipt_preserves_method_extension_fields() {
        let json = r#"{"status":"success","method":"tempo","timestamp":"2024-01-01T00:00:00Z","reference":"0xabc123","originTxHash":"0xdef456"}"#;
        let parsed = parse_receipt(&base64url_encode(json.as_bytes())).unwrap();

        assert_eq!(parsed.extensions["originTxHash"], "0xdef456");

        let reparsed = parse_receipt(&format_receipt(&parsed).unwrap()).unwrap();
        assert_eq!(reparsed.extensions["originTxHash"], "0xdef456");
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
        assert!(matches!(result, Err(MppError::MalformedCredential(_))));
    }

    #[test]
    fn test_parse_authorization_invalid_base64url() {
        let result = parse_authorization("Payment !");
        assert!(matches!(result, Err(MppError::MalformedCredential(_))));
    }

    #[test]
    fn test_parse_authorization_invalid_json() {
        let token = base64url_encode(b"not valid json");
        let result = parse_authorization(&format!("Payment {}", token));
        assert!(matches!(result, Err(MppError::MalformedCredential(_))));
    }

    #[test]
    fn test_parse_authorization_missing_challenge_fields() {
        let json = r#"{"challenge":{"id":"abc"},"payload":{}}"#;
        let token = base64url_encode(json.as_bytes());
        let result = parse_authorization(&format!("Payment {}", token));
        assert!(matches!(result, Err(MppError::MalformedCredential(_))));
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
        assert!(matches!(result, Err(MppError::InvalidReceipt(_))));
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
        assert!(matches!(result, Err(MppError::MalformedCredential(_))));
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
        assert!(matches!(result, Err(MppError::MalformedCredential(_))));
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
    fn test_parse_www_authenticate_rejects_oversized_request_parameter() {
        let oversized_request = "a".repeat(MAX_TOKEN_LEN + 1);
        let header = format!(
            r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="{}""#,
            oversized_request
        );

        let err = parse_www_authenticate(&header).unwrap_err();
        assert!(err.to_string().contains("Request parameter exceeds"));
    }

    #[test]
    fn test_parse_www_authenticate_accepts_request_parameter_at_the_limit() {
        let json = format!(r#"{{"a":"{}"}}"#, "x".repeat(MAX_TOKEN_LEN / 4 * 3 - 8));
        let request = base64url_encode(json.as_bytes());
        assert_eq!(request.len(), MAX_TOKEN_LEN);

        for value in [format!("\"{request}\""), request.clone()] {
            let header = format!(
                r#"Payment id="abc", realm="api", method="tempo", intent="charge", request={value}"#
            );
            let challenge = parse_www_authenticate(&header).unwrap();
            assert_eq!(challenge.request.raw(), request);
        }
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
    fn test_extract_payment_scheme_accepts_tab() {
        assert_eq!(
            extract_payment_scheme("Bearer xxx, pAyMeNt\teyJhYmMi"),
            Some("pAyMeNt\teyJhYmMi")
        );
        assert!(extract_payment_scheme("PaymentX eyJhYmMi").is_none());
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
    fn test_parse_www_authenticate_accepts_mixed_case_param_names() {
        let header =
            r#"Payment ID="abc123", Realm="api", Method="tempo", Intent="charge", Request="e30""#;
        let challenge = parse_www_authenticate(header).unwrap();
        assert_eq!(challenge.id, "abc123");
        assert_eq!(challenge.realm, "api");
        assert_eq!(challenge.method.as_str(), "tempo");
        assert_eq!(challenge.intent.as_str(), "charge");
    }

    #[test]
    fn test_parse_www_authenticate_rejects_case_variant_duplicate_params() {
        let header = r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30", ID="b""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Duplicate parameter: ID"));
    }

    #[test]
    fn test_parse_www_authenticate_rejects_empty_id() {
        let header =
            r#"Payment id="", realm="api", method="tempo", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Empty 'id'"));
    }

    #[test]
    fn test_parse_www_authenticate_accepts_canonical_method_names() {
        for method in ["tempo", "x402", "tempo-v2", "a:b", "a_b", "a1:b_2-c"] {
            let header = format!(
                r#"Payment id="abc", realm="api", method="{method}", intent="charge", request="e30""#
            );
            let challenge = parse_www_authenticate(&header).unwrap();
            assert_eq!(challenge.method.as_str(), method);
        }
    }

    #[test]
    fn test_parse_www_authenticate_rejects_invalid_method_name_digit_prefix() {
        let header =
            r#"Payment id="abc", realm="api", method="1tempo", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header).unwrap_err();
        assert!(err.to_string().contains("Invalid method"));
    }

    #[test]
    fn test_parse_www_authenticate_rejects_invalid_method_names() {
        for method in [
            "", "123", "-tempo", ":tempo", "_tempo", "*", "tempo!", "Tempo",
        ] {
            let header = format!(
                r#"Payment id="abc", realm="api", method="{method}", intent="charge", request="e30""#
            );
            let err = parse_www_authenticate(&header).unwrap_err();
            assert!(err.to_string().contains("Invalid method"));
        }
    }

    #[test]
    fn test_parse_www_authenticate_decodes_unicode_escapes() {
        for (escaped, expected) in [
            (
                r"em dash \u2014 and coffee \u2615",
                "em dash \u{2014} and coffee \u{2615}",
            ),
            (r"grinning \ud83d\ude00 face", "grinning \u{1f600} face"),
            ("café naïve", "café naïve"),
            (r"lone \ud83d here", "lone \u{fffd} here"),
            (r"lone \ude00 here", "lone \u{fffd} here"),
            (r"not an escape \\u2014", r"not an escape \u2014"),
            (r"short \u12 tail", "short u12 tail"),
            (r"ascii api\u0061", "ascii apia"),
        ] {
            let header = format!(
                r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="e30", description="{escaped}""#
            );
            let challenge = parse_www_authenticate(&header).unwrap();
            assert_eq!(
                challenge.description.as_deref(),
                Some(expected),
                "{escaped}"
            );
        }
    }

    #[test]
    fn test_format_www_authenticate_escapes_unicode_as_utf16() {
        let mut challenge = test_challenge();
        challenge.description = Some("Payment \u{2014} coffee \u{2615} \u{1f600}".to_string());

        let header = format_www_authenticate(&challenge).unwrap();

        assert!(header.contains(r#"description="Payment \u2014 coffee \u2615 \ud83d\ude00""#));
        let parsed = parse_www_authenticate(&header).unwrap();
        assert_eq!(parsed.description, challenge.description);
        assert_eq!(parsed.realm, challenge.realm);
        assert_eq!(parsed.method, challenge.method);
        assert_eq!(parsed.intent, challenge.intent);
    }

    #[test]
    fn test_format_www_authenticate_emits_valid_header_values() {
        for text in [
            "caf\u{e9} \u{a3}5",
            "bell\u{7}",
            "\u{0}\u{1}\u{1f}\u{7f}\u{80}\u{ff}",
            "tab\there",
            "1 \u{d7} Classmatic \u{2014} General Admission \u{1f39f}\u{fe0f}",
        ] {
            let mut challenge = test_challenge();
            challenge.realm = text.to_string();
            challenge.description = Some(text.to_string());

            let header = format_www_authenticate(&challenge).unwrap();
            assert!(
                header
                    .bytes()
                    .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte)),
                "{header:?}"
            );
            let value = axum::http::HeaderValue::from_str(&header).unwrap();
            let parsed = parse_www_authenticate(value.to_str().unwrap()).unwrap();
            assert_eq!(parsed.realm, text);
            assert_eq!(parsed.description.as_deref(), Some(text));
        }
    }

    #[test]
    fn test_format_www_authenticate_rejects_line_breaks() {
        for text in ["Line one\r\nLine two", "Line one\nLine two", "Line one\r"] {
            let mut challenge = test_challenge();
            challenge.description = Some(text.to_string());
            assert!(format_www_authenticate(&challenge).is_err(), "{text:?}");
        }
    }

    #[test]
    fn test_format_www_authenticate_rejects_unparseable_challenges() {
        let mut empty_id = test_challenge();
        empty_id.id = String::new();

        let mut invalid_method = test_challenge();
        invalid_method.method = "a b".into();

        let mut invalid_base64 = test_challenge();
        invalid_base64.request = Base64UrlJson::from_raw("not-valid!!!");

        let mut invalid_json = test_challenge();
        invalid_json.request = Base64UrlJson::from_raw("bm90IGpzb24");

        let mut invalid_intent = test_challenge();
        invalid_intent.intent = "payment plan".into();

        let mut request_not_object = test_challenge();
        request_not_object.request = Base64UrlJson::from_raw("W10");

        let mut invalid_opaque = test_challenge();
        invalid_opaque.opaque = Some(Base64UrlJson::from_raw("a|b"));

        for challenge in [
            empty_id,
            invalid_method,
            invalid_base64,
            invalid_json,
            invalid_intent,
            request_not_object,
            invalid_opaque,
        ] {
            assert!(
                format_www_authenticate(&challenge).is_err(),
                "{challenge:?}"
            );
        }
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
        assert!(matches!(err, MppError::InvalidReceipt(_)));
        assert!(err.to_string().contains("timestamp"));
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

    fn second_challenge_header() -> &'static str {
        r#"Payment id="second", realm="api.example.com", method="tempo", intent="charge", request="e30""#
    }

    #[test]
    fn test_parse_www_authenticate_all_ignores_scheme_like_text_in_quoted_values() {
        type Field = (
            fn(&mut PaymentChallenge, &str),
            fn(&PaymentChallenge) -> &str,
        );
        let description: Field = (
            |c, v| c.description = Some(v.to_string()),
            |c| c.description.as_deref().unwrap(),
        );
        let id: Field = (|c, v| c.id = v.to_string(), |c| &c.id);
        let realm: Field = (|c, v| c.realm = v.to_string(), |c| &c.realm);

        let cases = [
            (description, "Agentcash card payment test"),
            (description, "Payment at the start"),
            (description, r#"Use "Payment now", then retry \"#),
            (description, "comma, Payment fake challenge"),
            (id, "id with Payment text"),
            (realm, "Payment realm"),
        ];

        for ((set, get), value) in cases {
            let mut first = test_challenge();
            first.id = "first".to_string();
            set(&mut first, value);
            let header = format!(
                "{}, {}",
                format_www_authenticate(&first).unwrap(),
                second_challenge_header()
            );

            let results = parse_www_authenticate_all([header.as_str()]);
            assert_eq!(results.len(), 2, "{value:?}: {results:?}");
            assert_eq!(get(results[0].as_ref().unwrap()), value);
            assert_eq!(results[1].as_ref().unwrap().id, "second");
        }
    }

    #[test]
    fn test_parse_www_authenticate_all_among_other_schemes() {
        let header = format!(
            "Bearer error_description=\"use Payment challenge\", {}, \
             Digest realm=\"fallback Payment realm\", {}",
            r#"Payment id="first", realm="api.example.com", method="stripe", intent="charge", request="e30""#,
            second_challenge_header().replacen("Payment ", "pAyMeNt\t", 1),
        );

        let ids: Vec<_> = parse_www_authenticate_all([header.as_str()])
            .into_iter()
            .map(|result| result.unwrap().id)
            .collect();
        assert_eq!(ids, ["first", "second"]);
    }

    #[test]
    fn test_parse_www_authenticate_all_ignores_payment_inside_other_scheme() {
        for header in [
            r#"Bearer error_description="use Payment challenge""#,
            r#"Bearer realm="x, Payment id=evil, realm=api, method=tempo, intent=charge, request=e30, x=y""#,
        ] {
            assert!(parse_www_authenticate_all([header]).is_empty(), "{header}");
        }
    }

    #[test]
    fn test_parse_www_authenticate_accepts_whitespace_around_equals() {
        let header =
            "Payment id = \"abc\", realm= \"api\", method =\"tempo\", intent\t=\t\"charge\", request = e30";
        let parsed = parse_www_authenticate(header).unwrap();
        assert_eq!(parsed.id, "abc");
        assert_eq!(parsed.realm, "api");
        assert_eq!(parsed.method.as_str(), "tempo");
        assert_eq!(parsed.intent.as_str(), "charge");
        assert_eq!(parsed.request.raw(), "e30");
    }

    #[test]
    fn test_parse_www_authenticate_keeps_empty_trailing_param() {
        for tail in ["description=", "description=,", "description=,\t"] {
            let header = format!(
                r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="e30", {tail}"#
            );
            let single = parse_www_authenticate(&header).unwrap();
            assert_eq!(single.description.as_deref(), Some(""), "{header:?}");
            let all = parse_www_authenticate_all([header.as_str()]);
            let listed = all[0].as_ref().unwrap();
            assert_eq!(listed.description.as_deref(), Some(""), "{header:?}");
        }
    }

    #[test]
    fn test_parse_www_authenticate_advertises_payment_authorization_header() {
        let header = concat!(
            r#"Payment id="abc", realm="api", method="tempo", intent="charge", "#,
            r#"request="e30", header="Payment-Authorization""#,
        );
        let parsed = parse_www_authenticate(header).unwrap();
        assert_eq!(parsed.header.as_deref(), Some("Payment-Authorization"));
        assert_eq!(parsed.credential_header(), "Payment-Authorization");
    }

    #[test]
    fn test_parse_www_authenticate_omits_default_authorization_header() {
        let header = concat!(
            r#"Payment id="abc", realm="api", method="tempo", intent="charge", "#,
            r#"request="e30", header="Authorization""#,
        );
        let parsed = parse_www_authenticate(header).unwrap();
        assert!(parsed.header.is_none());
        assert_eq!(parsed.credential_header(), "Authorization");
        assert!(!format_www_authenticate(&parsed)
            .unwrap()
            .contains("header="));
    }

    #[test]
    fn test_parse_www_authenticate_rejects_unsupported_credential_header() {
        for name in [
            "not a header",
            "Cookie",
            "Proxy-Authorization",
            "Content-Length",
            "X-Payment-Authorization",
        ] {
            let header = format!(
                r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="e30", header="{name}""#,
            );
            let err = parse_www_authenticate(&header).unwrap_err();
            assert!(
                err.to_string().contains("Unsupported credential header"),
                "{name}: {err}"
            );
        }
    }

    #[test]
    fn test_parse_www_authenticate_keeps_credential_header_spelling() {
        let header = concat!(
            r#"Payment id="abc", realm="api", method="tempo", intent="charge", "#,
            r#"request="e30", header="payment-authorization""#,
        );
        let parsed = parse_www_authenticate(header).unwrap();
        assert_eq!(parsed.header.as_deref(), Some("payment-authorization"));
        assert_eq!(parsed.credential_header(), "payment-authorization");
    }

    #[test]
    fn test_format_www_authenticate_rejects_unsupported_credential_header() {
        let mut challenge = test_challenge();
        challenge.header = Some("Cookie".to_string());
        assert!(format_www_authenticate(&challenge).is_err());
    }

    #[test]
    fn test_parse_authorization_rejects_unsupported_credential_header() {
        let mut challenge = test_challenge();
        challenge.header = Some("Cookie".to_string());
        let credential =
            PaymentCredential::new(challenge.to_echo(), PaymentPayload::transaction("0xabc"));
        let header = format_authorization(&credential).unwrap();
        assert!(matches!(
            parse_authorization(&header),
            Err(MppError::MalformedCredential(_))
        ));
    }

    fn wire_challenge(overrides: &[(&str, &str)]) -> serde_json::Value {
        let mut challenge = serde_json::json!({
            "id": "abc",
            "realm": "api",
            "method": "tempo",
            "intent": "charge",
            "request": "e30",
        });
        for (key, value) in overrides {
            challenge[*key] = (*value).into();
        }
        challenge
    }

    fn parse_wire_challenge_as_header(challenge: &serde_json::Value) -> Result<PaymentChallenge> {
        let params: Vec<String> = challenge
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| format!("{key}=\"{}\"", value.as_str().unwrap()))
            .collect();
        parse_www_authenticate(&format!("Payment {}", params.join(", ")))
    }

    fn parse_wire_challenge_as_echo(challenge: &serde_json::Value) -> Result<PaymentCredential> {
        let credential = serde_json::json!({
            "challenge": challenge,
            "payload": {"type": "transaction", "signature": "0xabc"},
        });
        parse_authorization(&format!(
            "Payment {}",
            base64url_encode(credential.to_string().as_bytes())
        ))
    }

    #[test]
    fn test_bound_fields_are_validated_on_every_wire_path() {
        for case in [
            ("id", ""),
            ("intent", ""),
            ("intent", "Charge Me"),
            ("intent", "charge|x"),
            // `[]`
            ("request", "W10"),
            ("request", "e30|e30"),
            // `not json`
            ("request", "bm90IGpzb24"),
            ("expires", "tomorrow"),
            ("expires", "2025-01-15T12:00:00Z|x"),
            ("digest", "sha-512=abc"),
            ("digest", "sha-256=X|Payment-Authorization"),
            ("opaque", "Payment-Authorization|"),
            ("opaque", "not base64url"),
        ] {
            let challenge = wire_challenge(&[case]);
            assert!(
                parse_wire_challenge_as_header(&challenge).is_err(),
                "header: {case:?}"
            );
            assert!(
                serde_json::from_value::<PaymentChallenge>(challenge.clone()).is_err(),
                "serde: {case:?}"
            );
            assert!(
                matches!(
                    parse_wire_challenge_as_echo(&challenge),
                    Err(MppError::MalformedCredential(_))
                ),
                "echo: {case:?}"
            );
        }
    }

    #[test]
    fn test_bound_fields_are_not_normalized() {
        let challenge = wire_challenge(&[
            ("intent", "Charge-2"),
            ("expires", "2025-01-15T12:00:00Z"),
            (
                "digest",
                "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
            ),
            ("opaque", "eyJwaSI6InBpXzEyMyJ9"),
            ("header", "Payment-Authorization"),
        ]);
        let from_header = parse_wire_challenge_as_header(&challenge).unwrap();
        let from_serde: PaymentChallenge = serde_json::from_value(challenge.clone()).unwrap();
        let echo = parse_wire_challenge_as_echo(&challenge).unwrap().challenge;

        assert_eq!(from_header.intent.as_str(), "Charge-2");
        assert_eq!(from_serde.intent.as_str(), "Charge-2");
        assert_eq!(echo.intent.as_str(), "Charge-2");
        assert_eq!(
            serde_json::to_value(&from_header).unwrap(),
            serde_json::to_value(&from_serde).unwrap()
        );
        assert_eq!(serde_json::to_value(&from_serde).unwrap(), challenge);
    }

    #[test]
    fn test_deserialized_challenge_header_matches_header_parser() {
        let challenge = wire_challenge(&[("header", "Cookie")]);
        assert!(parse_wire_challenge_as_header(&challenge).is_err());
        assert!(serde_json::from_value::<PaymentChallenge>(challenge).is_err());

        let challenge = wire_challenge(&[("header", "Authorization")]);
        let from_header = parse_wire_challenge_as_header(&challenge).unwrap();
        let from_serde: PaymentChallenge = serde_json::from_value(challenge).unwrap();
        assert_eq!(from_header.header, None);
        assert_eq!(from_serde.header, None);
    }

    /// Without field validation the `|`-joined HMAC input is ambiguous: a
    /// challenge bound to `Payment-Authorization` has the same id as one whose
    /// opaque is `Payment-Authorization|`.
    #[test]
    fn test_parse_authorization_rejects_shifted_hmac_slots() {
        let signed = PaymentChallenge::with_secret_key_full(
            "shifted-slot-secret",
            "api",
            "tempo",
            "charge",
            Base64UrlJson::from_raw("e30"),
            None,
            None,
            None,
            None,
            Some("Payment-Authorization"),
        );
        let shifted_id = crate::protocol::core::compute_challenge_id(
            "shifted-slot-secret",
            "api",
            "tempo",
            "charge",
            "e30",
            None,
            None,
            Some("Payment-Authorization|"),
        );
        assert_eq!(signed.id, shifted_id);

        let shifted = wire_challenge(&[("id", &signed.id), ("opaque", "Payment-Authorization|")]);
        assert!(parse_wire_challenge_as_echo(&shifted).is_err());
    }

    #[test]
    fn test_credential_echo_includes_description() {
        let mut challenge = test_challenge();
        challenge.description = Some("Pay for caf\u{e9}".to_string());
        let credential =
            PaymentCredential::new(challenge.to_echo(), PaymentPayload::transaction("0xabc"));
        let header = format_authorization(&credential).unwrap();

        let wire: serde_json::Value =
            serde_json::from_slice(&base64url_decode(&header[8..]).unwrap()).unwrap();
        assert_eq!(wire["challenge"]["description"], "Pay for caf\u{e9}");
        assert_eq!(
            parse_authorization(&header).unwrap().challenge.description,
            challenge.description
        );

        // Without a description the field is omitted.
        let credential = PaymentCredential::new(
            test_challenge().to_echo(),
            PaymentPayload::transaction("0xabc"),
        );
        let header = format_authorization(&credential).unwrap();
        let wire: serde_json::Value =
            serde_json::from_slice(&base64url_decode(&header[8..]).unwrap()).unwrap();
        assert!(wire["challenge"].get("description").is_none());
    }

    #[test]
    fn test_parse_authorization_accepts_legacy_object_opaque() {
        let opaque =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let challenge = PaymentChallenge::with_secret_key_full(
            "legacy-opaque-secret",
            "api.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_raw("eyJhbW91bnQiOiIxMDAwIn0"),
            None,
            None,
            None,
            Some(opaque),
            None,
        );
        let credential = |opaque: serde_json::Value| {
            let json = serde_json::json!({
                "challenge": {
                    "id": challenge.id,
                    "realm": "api.example.com",
                    "method": "tempo",
                    "intent": "charge",
                    "request": "eyJhbW91bnQiOiIxMDAwIn0",
                    "opaque": opaque,
                },
                "payload": {"type": "transaction", "signature": "0x1234"},
            });
            format!("Payment {}", base64url_encode(json.to_string().as_bytes()))
        };

        let echo = parse_authorization(&credential(serde_json::json!({"pi": "pi_3abc123XYZ"})))
            .unwrap()
            .challenge;
        let opaque = echo.opaque.as_ref().map(|opaque| opaque.raw());
        assert_eq!(opaque, Some("eyJwaSI6InBpXzNhYmMxMjNYWVoifQ"));
        assert_eq!(
            echo.id,
            crate::protocol::core::compute_challenge_id(
                "legacy-opaque-secret",
                &echo.realm,
                echo.method.as_str(),
                echo.intent.as_str(),
                echo.request.raw(),
                None,
                None,
                opaque,
            )
        );

        assert!(parse_authorization(&credential(serde_json::json!({"pi": 123}))).is_err());
        assert!(parse_authorization(&credential(serde_json::json!(["pi"]))).is_err());
    }

    #[test]
    fn test_credential_echo_roundtrip_includes_header() {
        let mut challenge = test_challenge();
        challenge.header = Some("Payment-Authorization".to_string());
        let credential =
            PaymentCredential::new(challenge.to_echo(), PaymentPayload::transaction("0xabc"));
        let header = format_authorization(&credential).unwrap();
        let parsed = parse_authorization(&header).unwrap();
        assert_eq!(
            parsed.challenge.header.as_deref(),
            Some("Payment-Authorization")
        );
    }
}
