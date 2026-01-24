//! Core type definitions for the Web Payment Auth protocol.
//!
//! This module contains foundational types that have ZERO heavy dependencies -
//! only serde, serde_json, and thiserror. No alloy, no blockchain-specific types.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::Deref;

use crate::error::{MppError, Result};

/// Payment method identifier (newtype over String).
///
/// Represents a payment method like "tempo", "base", "stripe", etc.
/// This is a simple string wrapper with no hardcoded variants - the method
/// layer interprets specific values.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::core::MethodName;
///
/// let method: MethodName = "tempo".into();
/// assert_eq!(method.as_str(), "tempo");
/// assert!(method.eq_ignore_ascii_case("TEMPO"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodName(String);

impl MethodName {
    /// Create a new method name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Get the method name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this method name matches another (case-insensitive).
    pub fn eq_ignore_ascii_case(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
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
        Self(s.to_string())
    }
}

impl From<String> for MethodName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Serialize for MethodName {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MethodName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// Payment intent identifier (newtype over String).
///
/// Represents a payment intent like "charge", "authorize", "subscription", etc.
/// This is a simple string wrapper with no hardcoded variants - the intents
/// layer interprets specific values.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::core::IntentName;
///
/// let intent: IntentName = "charge".into();
/// assert_eq!(intent.as_str(), "charge");
/// assert!(intent.is_charge());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntentName(String);

impl IntentName {
    /// Create a new intent name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Get the intent name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this is the "charge" intent.
    pub fn is_charge(&self) -> bool {
        self.0.eq_ignore_ascii_case("charge")
    }

    /// Check if this is the "authorize" intent.
    pub fn is_authorize(&self) -> bool {
        self.0.eq_ignore_ascii_case("authorize")
    }

    /// Check if this is the "subscription" intent.
    pub fn is_subscription(&self) -> bool {
        self.0.eq_ignore_ascii_case("subscription")
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
        Self(s.to_string())
    }
}

impl From<String> for IntentName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl Serialize for IntentName {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IntentName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
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
/// use mpp_rs::protocol::core::Base64UrlJson;
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
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let json = serde_json::to_string(value)?;
        let raw = base64url_encode(json.as_bytes());
        Ok(Self { raw })
    }

    /// Create from a serializable type by encoding it.
    pub fn from_typed<T: Serialize>(value: &T) -> Result<Self> {
        let json = serde_json::to_string(value)?;
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
        serde_json::from_slice(&bytes)
            .map_err(|e| MppError::InvalidChallenge(format!("Invalid JSON in base64url: {}", e)))
    }

    /// Decode to a typed struct.
    pub fn decode<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        let bytes = base64url_decode(&self.raw)?;
        serde_json::from_slice(&bytes).map_err(|e| {
            MppError::InvalidChallenge(format!("Failed to decode base64url JSON: {}", e))
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

const BASE64URL_CHARS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes to base64url (URL-safe, no padding).
pub fn base64url_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        output.push(BASE64URL_CHARS[b0 >> 2] as char);
        output.push(BASE64URL_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            output.push(BASE64URL_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        }
        if chunk.len() > 2 {
            output.push(BASE64URL_CHARS[b2 & 0x3f] as char);
        }
    }

    output
}

/// Decode base64url to bytes (handles both padded and unpadded).
pub fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Build decode table
    let mut decode_table = [255u8; 128];
    for (i, &c) in BASE64URL_CHARS.iter().enumerate() {
        decode_table[c as usize] = i as u8;
    }
    // Also accept + and / for standard base64 compatibility
    decode_table[b'+' as usize] = 62;
    decode_table[b'/' as usize] = 63;

    // Strip padding
    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let chars: Vec<u8> = input
        .bytes()
        .map(|c| {
            if c >= 128 {
                255
            } else {
                decode_table[c as usize]
            }
        })
        .collect();

    // Check for invalid characters
    if chars.contains(&255) {
        return Err(MppError::InvalidBase64Url(
            "Invalid character in base64url".to_string(),
        ));
    }

    for chunk in chars.chunks(4) {
        let len = chunk.len();
        if len < 2 {
            return Err(MppError::InvalidBase64Url(
                "Invalid base64url length".to_string(),
            ));
        }

        let b0 = chunk[0] as usize;
        let b1 = chunk[1] as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        let b3 = chunk.get(3).copied().unwrap_or(0) as usize;

        output.push(((b0 << 2) | (b1 >> 4)) as u8);
        if len > 2 {
            output.push((((b1 & 0x0f) << 4) | (b2 >> 2)) as u8);
        }
        if len > 3 {
            output.push((((b2 & 0x03) << 6) | b3) as u8);
        }
    }

    Ok(output)
}

/// Payment protocol detected from HTTP 402 response.
///
/// Used to determine how to handle a payment-required response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentProtocol {
    /// Web Payment Auth (IETF draft) - uses WWW-Authenticate/Authorization headers
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
/// Indicates what kind of data is in the payload signature field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub enum PayloadType {
    /// Signed blockchain transaction (to be broadcast by server)
    #[default]
    Transaction,
    /// Key authorization signature (for authorize/subscription intents)
    KeyAuthorization,
    /// Transaction hash (already broadcast by client)
    Hash,
}

impl fmt::Display for PayloadType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transaction => write!(f, "transaction"),
            Self::KeyAuthorization => write!(f, "keyAuthorization"),
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
    /// Payment failed
    Failed,
}

impl fmt::Display for ReceiptStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failed => write!(f, "failed"),
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
        assert!(!intent.is_authorize());

        let intent2 = IntentName::new("AUTHORIZE");
        assert!(intent2.is_authorize());
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
    fn test_base64url_json() {
        let value = serde_json::json!({"amount": "1000", "currency": "USDC"});
        let b64 = Base64UrlJson::from_value(&value).unwrap();

        let decoded = b64.decode_value().unwrap();
        assert_eq!(decoded["amount"], "1000");
        assert_eq!(decoded["currency"], "USDC");

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
            serde_json::to_string(&PayloadType::KeyAuthorization).unwrap(),
            "\"keyAuthorization\""
        );
    }

    #[test]
    fn test_receipt_status_serde() {
        assert_eq!(
            serde_json::to_string(&ReceiptStatus::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&ReceiptStatus::Failed).unwrap(),
            "\"failed\""
        );
    }
}
