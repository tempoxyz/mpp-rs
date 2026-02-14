//! Authorize intent request type.
//!
//! The authorize intent represents a pre-authorization for later capture.
//! This module provides the `AuthorizeRequest` type with string-only fields -
//! no typed helpers like `amount_u256()`. Those are provided by the methods layer.

use serde::{Deserialize, Serialize};

use crate::error::{MppError, Result};

/// Authorize request (for authorize intent).
///
/// Represents a pre-authorization for later capture. All fields are strings
/// to remain method-agnostic. Use the methods layer for typed accessors.
///
/// # Examples
///
/// ```
/// use mpp::protocol::intents::AuthorizeRequest;
///
/// let req = AuthorizeRequest {
///     amount: "1000000".to_string(),
///     currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
///     recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
///     description: Some("Pre-auth for API usage".to_string()),
///     expires: None,
///     external_id: None,
///     max_amount: Some("5000000".to_string()),
///     valid_until: Some("2025-12-31T23:59:59Z".to_string()),
///     method_details: None,
/// };
///
/// assert_eq!(req.amount, "1000000");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizeRequest {
    /// Amount in base units (e.g., wei, satoshi, cents)
    pub amount: String,

    /// Currency/asset identifier (token address, ISO 4217 code, or symbol)
    pub currency: String,

    /// Recipient address (optional, server may be recipient)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Request expiration (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Merchant reference ID
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Maximum amount that can be captured
    #[serde(rename = "maxAmount", skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<String>,

    /// Authorization validity deadline (ISO 8601)
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,

    /// Method-specific extension fields (interpreted by methods layer)
    #[serde(rename = "methodDetails", skip_serializing_if = "Option::is_none")]
    pub method_details: Option<serde_json::Value>,
}

impl AuthorizeRequest {
    /// Parse the amount as u128.
    ///
    /// Returns an error if the amount is not a valid unsigned integer.
    pub fn parse_amount(&self) -> Result<u128> {
        self.amount
            .parse()
            .map_err(|_| MppError::InvalidAmount(format!("Invalid amount: {}", self.amount)))
    }

    /// Validate that the authorize amount does not exceed a maximum.
    ///
    /// # Arguments
    /// * `max_amount` - Maximum allowed amount as a string (atomic units)
    ///
    /// # Returns
    /// * `Ok(())` if amount is within limit
    /// * `Err(AmountExceedsMax)` if amount exceeds the maximum
    pub fn validate_max_amount(&self, max_amount: &str) -> Result<()> {
        let amount = self.parse_amount()?;
        let max: u128 = max_amount
            .parse()
            .map_err(|_| MppError::InvalidAmount(format!("Invalid max amount: {}", max_amount)))?;

        if amount > max {
            return Err(MppError::AmountExceedsMax {
                required: amount,
                max,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorize_request_serialization() {
        let req = AuthorizeRequest {
            amount: "10000".to_string(),
            currency: "0x123".to_string(),
            recipient: Some("0x456".to_string()),
            description: Some("Pre-auth".to_string()),
            expires: Some("2024-01-01T00:00:00Z".to_string()),
            external_id: None,
            max_amount: Some("50000".to_string()),
            valid_until: Some("2024-06-01T00:00:00Z".to_string()),
            method_details: Some(serde_json::json!({
                "chainId": 42431,
                "feePayer": true
            })),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"amount\":\"10000\""));
        assert!(json.contains("\"maxAmount\":\"50000\""));
        assert!(json.contains("\"validUntil\":\"2024-06-01T00:00:00Z\""));
        assert!(json.contains("\"methodDetails\""));
        assert!(json.contains("\"chainId\":42431"));

        let parsed: AuthorizeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.amount, "10000");
        assert_eq!(parsed.max_amount.as_deref(), Some("50000"));
    }

    #[test]
    fn test_authorize_request_optional_fields_omitted() {
        let req = AuthorizeRequest {
            amount: "500".to_string(),
            currency: "USD".to_string(),
            ..Default::default()
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("recipient"));
        assert!(!json.contains("description"));
        assert!(!json.contains("expires"));
        assert!(!json.contains("externalId"));
        assert!(!json.contains("maxAmount"));
        assert!(!json.contains("validUntil"));
        assert!(!json.contains("methodDetails"));
    }

    #[test]
    fn test_authorize_request_deserialization() {
        let json = r#"{"amount":"2000","currency":"0xabc","maxAmount":"10000"}"#;
        let parsed: AuthorizeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.amount, "2000");
        assert_eq!(parsed.currency, "0xabc");
        assert_eq!(parsed.max_amount.as_deref(), Some("10000"));
        assert!(parsed.recipient.is_none());
        assert!(parsed.valid_until.is_none());
        assert!(parsed.method_details.is_none());
    }

    #[test]
    fn test_parse_amount() {
        let req = AuthorizeRequest {
            amount: "1000000".to_string(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 1_000_000u128);

        let invalid = AuthorizeRequest {
            amount: "not-a-number".to_string(),
            ..Default::default()
        };
        assert!(invalid.parse_amount().is_err());
    }

    #[test]
    fn test_validate_max_amount() {
        let req = AuthorizeRequest {
            amount: "1000".to_string(),
            ..Default::default()
        };

        assert!(req.validate_max_amount("2000").is_ok());
        assert!(req.validate_max_amount("1000").is_ok());
        assert!(req.validate_max_amount("500").is_err());
    }
}
