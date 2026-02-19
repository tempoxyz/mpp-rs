//! Session intent request type.
//!
//! The session intent represents a pay-as-you-go session payment request.
//! This module provides the `SessionRequest` type with string-only fields -
//! no typed helpers like `amount_u256()`. Those are provided by the methods layer.

use serde::{Deserialize, Serialize};

use crate::error::{MppError, Result};

/// Session request (for session intent).
///
/// Represents a pay-as-you-go session payment request. All fields are strings
/// to remain method-agnostic. Use the methods layer for typed accessors.
///
/// # Examples
///
/// ```
/// use mpp::protocol::intents::SessionRequest;
///
/// let req = SessionRequest {
///     amount: "1000".to_string(),
///     unit_type: Some("second".to_string()),
///     currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
///     decimals: None,
///     recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
///     suggested_deposit: Some("60000".to_string()),
///     method_details: None,
/// };
///
/// assert_eq!(req.amount, "1000");
/// assert_eq!(req.unit_type, Some("second".to_string()));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionRequest {
    /// Amount per unit in base units (e.g., wei per second)
    pub amount: String,

    /// Unit type for the session rate (e.g., "second", "minute", "request"). Optional.
    #[serde(rename = "unitType", skip_serializing_if = "Option::is_none")]
    pub unit_type: Option<String>,

    /// Currency/asset identifier (token address, ISO 4217 code, or symbol)
    pub currency: String,

    /// Token decimals for amount conversion (e.g., 6 for pathUSD).
    ///
    /// When set, `amount` and `suggested_deposit` are treated as human-readable
    /// values and will be scaled by `10^decimals` during challenge creation.
    /// The field is stripped from wire serialization.
    #[serde(skip)]
    pub decimals: Option<u8>,

    /// Recipient address (optional, server may be recipient)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// Suggested deposit amount in base units
    #[serde(rename = "suggestedDeposit", skip_serializing_if = "Option::is_none")]
    pub suggested_deposit: Option<String>,

    /// Method-specific extension fields (interpreted by methods layer)
    #[serde(rename = "methodDetails", skip_serializing_if = "Option::is_none")]
    pub method_details: Option<serde_json::Value>,
}

impl SessionRequest {
    /// Apply the decimals transform, converting human-readable amounts to base units.
    ///
    /// Transforms both `amount` and `suggested_deposit` (if present).
    /// If `decimals` is `None`, returns `self` unchanged.
    pub fn with_base_units(mut self) -> Result<Self> {
        if let Some(decimals) = self.decimals {
            self.amount = super::parse_units(&self.amount, decimals)?;
            if let Some(ref deposit) = self.suggested_deposit {
                self.suggested_deposit = Some(super::parse_units(deposit, decimals)?);
            }
            self.decimals = None;
        }
        Ok(self)
    }

    /// Parse the amount as u128.
    ///
    /// Returns an error if the amount is not a valid unsigned integer.
    pub fn parse_amount(&self) -> Result<u128> {
        self.amount
            .parse()
            .map_err(|_| MppError::InvalidAmount(format!("Invalid amount: {}", self.amount)))
    }

    /// Validate that the session amount does not exceed a maximum.
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
    fn test_session_request_serialization() {
        let req = SessionRequest {
            amount: "1000".to_string(),
            unit_type: Some("second".to_string()),
            currency: "0x123".to_string(),
            recipient: Some("0x456".to_string()),
            suggested_deposit: Some("60000".to_string()),
            method_details: Some(serde_json::json!({
                "chainId": 42431,
                "feePayer": true
            })),
            ..Default::default()
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"amount\":\"1000\""));
        assert!(json.contains("\"unitType\":\"second\""));
        assert!(json.contains("\"suggestedDeposit\":\"60000\""));
        assert!(json.contains("\"methodDetails\""));
        assert!(json.contains("\"chainId\":42431"));

        let parsed: SessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.amount, "1000");
        assert_eq!(parsed.unit_type, Some("second".to_string()));
        assert_eq!(parsed.suggested_deposit.as_deref(), Some("60000"));
    }

    #[test]
    fn test_session_request_optional_fields_omitted() {
        let req = SessionRequest {
            amount: "500".to_string(),
            unit_type: Some("request".to_string()),
            currency: "USD".to_string(),
            ..Default::default()
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("recipient"));
        assert!(!json.contains("suggestedDeposit"));
        assert!(!json.contains("methodDetails"));
    }

    #[test]
    fn test_session_request_deserialization() {
        let json = r#"{"amount":"2000","unitType":"minute","currency":"0xabc"}"#;
        let parsed: SessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.amount, "2000");
        assert_eq!(parsed.unit_type, Some("minute".to_string()));
        assert_eq!(parsed.currency, "0xabc");
        assert!(parsed.recipient.is_none());
        assert!(parsed.suggested_deposit.is_none());
        assert!(parsed.method_details.is_none());
    }

    #[test]
    fn test_parse_amount() {
        let req = SessionRequest {
            amount: "1000000".to_string(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 1_000_000u128);

        let invalid = SessionRequest {
            amount: "not-a-number".to_string(),
            ..Default::default()
        };
        assert!(invalid.parse_amount().is_err());
    }

    #[test]
    fn test_validate_max_amount() {
        let req = SessionRequest {
            amount: "1000".to_string(),
            ..Default::default()
        };

        assert!(req.validate_max_amount("2000").is_ok());
        assert!(req.validate_max_amount("1000").is_ok());
        assert!(req.validate_max_amount("500").is_err());
    }

    #[test]
    fn test_with_base_units() {
        let req = SessionRequest {
            amount: "1.5".to_string(),
            unit_type: Some("second".to_string()),
            currency: "0x123".to_string(),
            decimals: Some(6),
            suggested_deposit: Some("60".to_string()),
            ..Default::default()
        };
        let converted = req.with_base_units().unwrap();
        assert_eq!(converted.amount, "1500000");
        assert_eq!(converted.suggested_deposit.as_deref(), Some("60000000"));
        assert!(converted.decimals.is_none());
    }

    #[test]
    fn test_with_base_units_no_decimals() {
        let req = SessionRequest {
            amount: "1000000".to_string(),
            unit_type: Some("second".to_string()),
            currency: "0x123".to_string(),
            ..Default::default()
        };
        let converted = req.with_base_units().unwrap();
        assert_eq!(converted.amount, "1000000");
    }

    #[test]
    fn test_session_request_without_unit_type() {
        let json = r#"{"amount":"2000","currency":"0xabc"}"#;
        let parsed: SessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.amount, "2000");
        assert!(parsed.unit_type.is_none());
    }
}
