//! Charge intent request type.
//!
//! The charge intent represents a one-time payment request. This module provides
//! the `ChargeRequest` type with string-only fields - no typed helpers like
//! `amount_u256()`. Those are provided by the methods layer (e.g., `methods::evm`).

use serde::{Deserialize, Serialize};

use crate::error::{MppError, Result};

/// Charge request (for charge intent).
///
/// Represents a one-time payment request. All fields are strings to remain
/// method-agnostic. Use the methods layer for typed accessors.
///
/// # Examples
///
/// ```
/// use mpay::protocol::intents::ChargeRequest;
///
/// let req = ChargeRequest {
///     amount: "1000000".to_string(),
///     currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
///     recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
///     expires: None,
///     description: Some("API access".to_string()),
///     external_id: None,
///     method_details: None,
/// };
///
/// assert_eq!(req.amount, "1000000");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChargeRequest {
    /// Amount in base units (e.g., wei, satoshi, cents)
    pub amount: String,

    /// Currency/asset identifier (token address, ISO 4217 code, or symbol)
    pub currency: String,

    /// Recipient address (optional, server may be recipient)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// Request expiration (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Merchant reference ID
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Method-specific extension fields (interpreted by methods layer)
    #[serde(rename = "methodDetails", skip_serializing_if = "Option::is_none")]
    pub method_details: Option<serde_json::Value>,
}

impl ChargeRequest {
    /// Parse the amount as u128.
    ///
    /// Returns an error if the amount is not a valid unsigned integer.
    pub fn parse_amount(&self) -> Result<u128> {
        self.amount
            .parse()
            .map_err(|_| MppError::InvalidAmount(format!("Invalid amount: {}", self.amount)))
    }

    /// Validate that the charge amount does not exceed a maximum.
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
    fn test_charge_request_serialization() {
        let req = ChargeRequest {
            amount: "10000".to_string(),
            currency: "0x123".to_string(),
            recipient: Some("0x456".to_string()),
            expires: Some("2024-01-01T00:00:00Z".to_string()),
            description: None,
            external_id: None,
            method_details: Some(serde_json::json!({
                "chainId": 88153,
                "feePayer": true
            })),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"amount\":\"10000\""));
        assert!(json.contains("\"methodDetails\""));
        assert!(json.contains("\"chainId\":88153"));

        let parsed: ChargeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.amount, "10000");
    }

    #[test]
    fn test_parse_amount() {
        let req = ChargeRequest {
            amount: "1000000".to_string(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 1_000_000u128);

        let invalid = ChargeRequest {
            amount: "not-a-number".to_string(),
            ..Default::default()
        };
        assert!(invalid.parse_amount().is_err());
    }

    #[test]
    fn test_validate_max_amount() {
        let req = ChargeRequest {
            amount: "1000".to_string(),
            ..Default::default()
        };

        assert!(req.validate_max_amount("2000").is_ok());
        assert!(req.validate_max_amount("1000").is_ok());
        assert!(req.validate_max_amount("500").is_err());
    }
}
