//! Core type definitions for the Web Payment Auth protocol.
//!
//! This module contains foundational types that have ZERO heavy dependencies -
//! only serde, serde_json, and thiserror. No alloy, no blockchain-specific types.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::Deref;

use crate::error::{MppError, Result};

/// Payment method identifier (newtype over String).
///
/// Represents a payment method like "tempo", "base", "stripe", etc.
/// Per spec, method identifiers MUST be lowercase ASCII strings.
/// This type validates and normalizes to lowercase on creation.
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::MethodName;
///
/// let method: MethodName = "tempo".into();
/// assert_eq!(method.as_str(), "tempo");
///
/// // Uppercase input is normalized to lowercase
/// let method2: MethodName = "TEMPO".into();
/// assert_eq!(method2.as_str(), "tempo");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MethodName(String);

impl MethodName {
    /// Create a new method name, normalizing to lowercase per spec.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into().to_ascii_lowercase())
    }

    /// Get the method name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this method name matches another (case-insensitive).
    pub fn eq_ignore_ascii_case(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }

    /// Check if the method name contains only valid ASCII lowercase characters.
    ///
    /// Per spec: `method-name = 1*LOWERALPHA` (a-z only).
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty() && self.0.chars().all(|c| c.is_ascii_lowercase())
    }
}

impl Deref for MethodName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for MethodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for MethodName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for MethodName {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// Payment intent identifier (newtype over String).
///
/// Represents a payment intent like "charge", "session", etc.
/// This is a simple string wrapper with no hardcoded variants - the intents
/// layer interprets specific values.
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::IntentName;
///
/// let intent: IntentName = "charge".into();
/// assert_eq!(intent.as_str(), "charge");
/// assert!(intent.is_charge());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IntentName(String);

impl IntentName {
    /// Create a new intent name, normalizing to lowercase per spec.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into().to_ascii_lowercase())
    }

    /// Get the intent name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this is the "charge" intent.
    pub fn is_charge(&self) -> bool {
        self.0.eq_ignore_ascii_case("charge")
    }

    /// Check if this is the "session" intent.
    pub fn is_session(&self) -> bool {
        self.0.eq_ignore_ascii_case("session")
    }
}

impl Deref for IntentName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for IntentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for IntentName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for IntentName {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// A JSON value encoded as base64url.
///
/// This type owns the raw base64url string and can decode it to a JSON Value
/// or a typed struct on demand. It preserves the original encoding for
/// credential echo (avoiding re-serialization issues).
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::Base64UrlJson;
/// use serde_json::json;
///
/// // Create from JSON value
/// let b64 = Base64UrlJson::from_value(&json!({"amount": "1000"})).unwrap();
///
/// // Get back the raw base64url string
/// assert!(!b64.raw().is_empty());
///
/// // Decode to Value
/// let value = b64.decode_value().unwrap();
/// assert_eq!(value["amount"], "1000");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Base64UrlJson {
    /// The raw base64url-encoded string (source of truth)
    raw: String,
}

impl Base64UrlJson {
    /// Create from a raw base64url string.
    ///
    /// This does not validate the string - use `decode_value()` or `decode::<T>()`
    /// to validate the encoding.
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }

    /// Create from a JSON Value by encoding it.
    #[must_use = "this returns a new Base64UrlJson and does not modify the input"]
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let json = serde_json_canonicalizer::to_string(value)?;
        let raw = base64url_encode(json.as_bytes());
        Ok(Self { raw })
    }

    /// Create from a serializable type by encoding it.
    pub fn from_typed<T: Serialize>(value: &T) -> Result<Self> {
        let json = serde_json_canonicalizer::to_string(value)?;
        let raw = base64url_encode(json.as_bytes());
        Ok(Self { raw })
    }

    /// Get the raw base64url string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Decode to a JSON Value.
    pub fn decode_value(&self) -> Result<serde_json::Value> {
        let bytes = base64url_decode(&self.raw)?;
        serde_json::from_slice(&bytes).map_err(|e| {
            MppError::invalid_challenge_reason(format!("Invalid JSON in base64url: {}", e))
        })
    }

    /// Decode to a typed struct.
    pub fn decode<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        let bytes = base64url_decode(&self.raw)?;
        serde_json::from_slice(&bytes).map_err(|e| {
            MppError::invalid_challenge_reason(format!("Failed to decode base64url JSON: {}", e))
        })
    }

    /// Check if the raw string is empty.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

impl Serialize for Base64UrlJson {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64UrlJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from_raw)
    }
}

/// Encode bytes as base64url (no padding).
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode a base64url string to bytes.
///
/// Accepts both URL-safe (`-`, `_`) and standard (`+`, `/`) alphabets,
/// with or without `=` padding. This follows Postel's law — be strict in
/// what you produce (see [`base64url_encode`]) but lenient in what you
/// accept — and aligns with the mppx TypeScript SDK which also accepts
/// both variants.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    // Normalize standard base64 to URL-safe alphabet and strip padding.
    let normalized: String = input
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();

    URL_SAFE_NO_PAD
        .decode(&normalized)
        .map_err(|e| MppError::InvalidBase64Url(format!("Invalid base64url: {}", e)))
}

/// Payment protocol detected from HTTP 402 response.
///
/// Used to determine how to handle a payment-required response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentProtocol {
    /// Web Payment Auth protocol - uses WWW-Authenticate/Authorization headers
    WebPaymentAuth,
}

impl PaymentProtocol {
    /// Detect the payment protocol from HTTP response headers.
    ///
    /// Returns `WebPaymentAuth` if the response has a `WWW-Authenticate: Payment ...` header,
    /// otherwise returns `None`.
    ///
    /// Detection is case-insensitive and tolerant of leading whitespace per RFC 7235.
    ///
    /// # Arguments
    /// * `www_authenticate` - The value of the WWW-Authenticate header, if present
    pub fn detect(www_authenticate: Option<&str>) -> Option<Self> {
        const PAYMENT_SCHEME_WITH_SPACE: &str = "payment ";

        match www_authenticate {
            Some(header) => {
                let trimmed = header.trim_start();
                if trimmed
                    .get(..PAYMENT_SCHEME_WITH_SPACE.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PAYMENT_SCHEME_WITH_SPACE))
                {
                    Some(Self::WebPaymentAuth)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Detect payment protocol from multiple header values.
    ///
    /// Returns `Some(WebPaymentAuth)` if any header matches.
    pub fn detect_any<'a>(headers: impl IntoIterator<Item = &'a str>) -> Option<Self> {
        headers.into_iter().find_map(|h| Self::detect(Some(h)))
    }

    /// Check if this is the Web Payment Auth protocol.
    pub fn is_web_payment_auth(&self) -> bool {
        matches!(self, Self::WebPaymentAuth)
    }
}

impl fmt::Display for PaymentProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebPaymentAuth => write!(f, "Web Payment Auth"),
        }
    }
}

/// Payment payload type.
///
/// Indicates what kind of data is in the payload. Per spec:
/// - `transaction`: Signed blockchain transaction (to be broadcast by server)
/// - `hash`: Transaction hash (already broadcast by client)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PayloadType {
    /// Signed blockchain transaction (to be broadcast by server)
    Transaction,
    /// Transaction hash (already broadcast by client)
    Hash,
}

impl fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction => write!(f, "transaction"),
            Self::Hash => write!(f, "hash"),
        }
    }
}

/// Payment receipt status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    /// Payment succeeded
    Success,
}

impl fmt::Display for ReceiptStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_name() {
        let method: MethodName = "tempo".into();
        assert_eq!(method.as_str(), "tempo");
        assert!(method.eq_ignore_ascii_case("TEMPO"));
        assert_eq!(method.to_string(), "tempo");
        assert!(method.is_valid());
    }

    #[test]
    fn test_method_name_normalizes_to_lowercase() {
        // Per spec, method identifiers MUST be lowercase
        let method: MethodName = "TEMPO".into();
        assert_eq!(method.as_str(), "tempo");

        let method2 = MethodName::new("TeMpO");
        assert_eq!(method2.as_str(), "tempo");
    }

    #[test]
    fn test_method_name_serde() {
        let method = MethodName::new("base");
        let json = serde_json::to_string(&method).unwrap();
        assert_eq!(json, "\"base\"");

        let parsed: MethodName = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, method);
    }

    #[test]
    fn test_intent_name() {
        let intent: IntentName = "charge".into();
        assert!(intent.is_charge());
        assert!(!intent.is_session());

        let intent2 = IntentName::new("SESSION");
        assert!(intent2.is_session());
        assert_eq!(intent2.as_str(), "session");
    }

    #[test]
    fn test_intent_name_normalizes_to_lowercase() {
        let intent: IntentName = "CHARGE".into();
        assert_eq!(intent.as_str(), "charge");

        let intent2 = IntentName::new("SeSsIoN");
        assert_eq!(intent2.as_str(), "session");
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_decode_rejects_invalid_characters() {
        let noisy = "YW!JjZA";
        assert!(base64url_decode(noisy).is_err());
    }

    #[test]
    fn test_base64url_decode_accepts_standard_base64_with_padding() {
        // Standard base64 ('+', '/') with '=' padding — as produced by
        // some servers that use RFC 4648 §4 instead of §5.
        let data = b"hello world";
        let standard = base64::engine::general_purpose::STANDARD.encode(data);
        assert!(standard.contains('=') || standard.contains('+') || standard.contains('/'));
        let decoded = base64url_decode(&standard).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_decode_accepts_url_safe_without_padding() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_decode_accepts_standard_alphabet_no_padding() {
        // Standard alphabet but padding stripped — another common variant.
        let data = b"test data with special chars: <>?";
        let standard = base64::engine::general_purpose::STANDARD.encode(data);
        let no_pad = standard.trim_end_matches('=');
        let decoded = base64url_decode(no_pad).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_json() {
        let value = serde_json::json!({"amount": "1000", "currency": "pathUSD"});
        let b64 = Base64UrlJson::from_value(&value).unwrap();

        let decoded = b64.decode_value().unwrap();
        assert_eq!(decoded["amount"], "1000");
        assert_eq!(decoded["currency"], "pathUSD");

        // Can also decode to typed
        #[derive(Deserialize)]
        struct TestRequest {
            amount: String,
        }
        let typed: TestRequest = b64.decode().unwrap();
        assert_eq!(typed.amount, "1000");
    }

    #[test]
    fn test_payment_protocol_detect() {
        assert_eq!(
            PaymentProtocol::detect(Some("Payment id=\"abc\"")),
            Some(PaymentProtocol::WebPaymentAuth)
        );
        assert_eq!(
            PaymentProtocol::detect(Some("payment id=\"abc\"")),
            Some(PaymentProtocol::WebPaymentAuth)
        );
        assert_eq!(
            PaymentProtocol::detect(Some("PAYMENT id=\"abc\"")),
            Some(PaymentProtocol::WebPaymentAuth)
        );
        assert_eq!(
            PaymentProtocol::detect(Some("  Payment id=\"abc\"")),
            Some(PaymentProtocol::WebPaymentAuth)
        );
        assert_eq!(PaymentProtocol::detect(Some("Bearer token")), None);
        assert_eq!(PaymentProtocol::detect(None), None);
    }

    #[test]
    fn test_payment_protocol_detect_any() {
        let headers = vec!["Bearer token", "Payment id=\"abc\"", "Basic xyz"];
        assert_eq!(
            PaymentProtocol::detect_any(headers.into_iter()),
            Some(PaymentProtocol::WebPaymentAuth)
        );

        let no_payment = vec!["Bearer token", "Basic xyz"];
        assert_eq!(PaymentProtocol::detect_any(no_payment.into_iter()), None);
    }

    #[test]
    fn test_payload_type_serde() {
        assert_eq!(
            serde_json::to_string(&PayloadType::Transaction).unwrap(),
            "\"transaction\""
        );
        assert_eq!(
            serde_json::to_string(&PayloadType::Hash).unwrap(),
            "\"hash\""
        );
    }

    #[test]
    fn test_base64url_json_special_characters() {
        let value = serde_json::json!({
            "text": "quotes \" and backslashes \\",
            "unicode": "€ 漢字",
            "url": "https://example.com/path?a=1&b=2"
        });
        let encoded = Base64UrlJson::from_value(&value).unwrap();
        let decoded: serde_json::Value = encoded.decode_value().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_receipt_status_serde() {
        assert_eq!(
            serde_json::to_string(&ReceiptStatus::Success).unwrap(),
            "\"success\""
        );
    }
}
