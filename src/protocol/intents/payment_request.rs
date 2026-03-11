//! Generic payment request helpers.
//!
//! This module provides a convenience API similar to the TypeScript SDK's
//! `PaymentRequest` helpers for serializing/deserializing request payloads.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::Result;
use crate::protocol::core::{base64url_decode, base64url_encode, PaymentChallenge};

/// Generic payment request value.
pub type Request = serde_json::Value;

/// Serialize a request into base64url JSON (no padding).
pub fn serialize<T: Serialize>(request: &T) -> Result<String> {
    let json = serde_json_canonicalizer::to_string(request)?;
    Ok(base64url_encode(json.as_bytes()))
}

/// Deserialize a base64url JSON request into a generic JSON value.
pub fn deserialize(encoded: &str) -> Result<Request> {
    let bytes = base64url_decode(encoded)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Deserialize a base64url JSON request into a typed struct.
pub fn deserialize_typed<T: DeserializeOwned>(encoded: &str) -> Result<T> {
    let bytes = base64url_decode(encoded)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Decode the request from a parsed challenge as a generic JSON value.
pub fn from_challenge(challenge: &PaymentChallenge) -> Result<Request> {
    challenge.request.decode_value()
}

/// Decode the request from a parsed challenge as a typed struct.
pub fn from_challenge_typed<T: DeserializeOwned>(challenge: &PaymentChallenge) -> Result<T> {
    challenge.request.decode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::Base64UrlJson;
    use crate::protocol::intents::ChargeRequest;

    #[test]
    fn test_serialize_is_base64url() {
        let serialized = serialize(&serde_json::json!({
            "amount": "1000000",
            "currency": "USD"
        }))
        .unwrap();

        assert!(serialized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(!serialized.contains('='));
    }

    #[test]
    fn test_roundtrip_generic_request() {
        let original = serde_json::json!({
            "amount": "1000000",
            "currency": "USD",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00"
        });

        let encoded = serialize(&original).unwrap();
        let decoded = deserialize(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_special_characters() {
        let original = serde_json::json!({
            "amount": "1000000",
            "description": "Payment for cafe & mas"
        });

        let encoded = serialize(&original).unwrap();
        let decoded = deserialize(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_deserialize_typed() {
        let original = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "USD".to_string(),
            recipient: Some("0x1234".to_string()),
            ..Default::default()
        };

        let encoded = serialize(&original).unwrap();
        let decoded: ChargeRequest = deserialize_typed(&encoded).unwrap();

        assert_eq!(decoded.amount, "1000000");
        assert_eq!(decoded.currency, "USD");
        assert_eq!(decoded.recipient.as_deref(), Some("0x1234"));
    }

    #[test]
    fn test_from_challenge() {
        let challenge = PaymentChallenge {
            id: "abc123".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "currency": "USD"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let request = from_challenge(&challenge).unwrap();
        assert_eq!(request["amount"], "1000");
        assert_eq!(request["currency"], "USD");
    }

    #[test]
    fn test_from_challenge_typed() {
        let request = ChargeRequest {
            amount: "1000".to_string(),
            currency: "USD".to_string(),
            recipient: Some("0x1234".to_string()),
            ..Default::default()
        };

        let challenge = PaymentChallenge {
            id: "abc123".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_typed(&request).unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let decoded: ChargeRequest = from_challenge_typed(&challenge).unwrap();
        assert_eq!(decoded.amount, "1000");
        assert_eq!(decoded.currency, "USD");
        assert_eq!(decoded.recipient.as_deref(), Some("0x1234"));
    }

    #[test]
    fn test_deserialize_invalid_base64url() {
        let result = deserialize("invalid!");
        assert!(result.is_err());
    }
}
