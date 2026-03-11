//! Charge intent request type.
//!
//! The charge intent represents a one-time payment request. This module provides
//! the `ChargeRequest` type with string-only fields - no typed helpers like
//! `amount_u256()`. Those are provided by the methods layer (e.g., `methods::evm`).

use serde::{Deserialize, Serialize};

use crate::error::{MppError, Result};
#[cfg(feature = "evm")]
use crate::evm::U256;

/// Charge request (for charge intent).
///
/// Represents a one-time payment request. All fields are strings to remain
/// method-agnostic. Use the methods layer for typed accessors.
///
/// # Examples
///
/// ```
/// use mpp::protocol::intents::ChargeRequest;
///
/// let req = ChargeRequest {
///     amount: "1000000".to_string(),
///     currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
///     decimals: None,
///     recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
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

    /// Token decimals for amount conversion (e.g., 6 for pathUSD).
    ///
    /// When set, the amount is treated as a human-readable value and will be
    /// scaled by `10^decimals` during challenge creation (matching the TS SDK's
    /// `parseUnits` transform). The field is stripped from wire serialization.
    #[serde(skip)]
    pub decimals: Option<u8>,

    /// Recipient address (optional, server may be recipient)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

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
    /// Apply the decimals transform, converting human-readable amount to base units.
    ///
    /// This matches the TypeScript SDK's `parseUnits(amount, decimals)` transform.
    /// For example, with `amount = "1.5"` and `decimals = 6`, returns a new
    /// `ChargeRequest` with `amount = "1500000"`.
    ///
    /// If `decimals` is `None`, returns `self` unchanged.
    pub fn with_base_units(mut self) -> Result<Self> {
        if let Some(decimals) = self.decimals {
            self.amount = super::parse_units(&self.amount, decimals)?;
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

    /// Parse the amount as U256 when EVM support is enabled.
    ///
    /// This matches bigint semantics in the TypeScript SDK and avoids the
    /// `u128` ceiling of [`parse_amount`].
    #[cfg(feature = "evm")]
    pub fn parse_amount_u256(&self) -> Result<U256> {
        crate::evm::parse_amount(&self.amount)
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
            description: None,
            external_id: None,
            method_details: Some(serde_json::json!({
                "chainId": 42431,
                "feePayer": true
            })),
            ..Default::default()
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"amount\":\"10000\""));
        assert!(json.contains("\"methodDetails\""));
        assert!(json.contains("\"chainId\":42431"));

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

    #[cfg(feature = "evm")]
    #[test]
    fn test_parse_amount_u256() {
        let req = ChargeRequest {
            amount: "340282366920938463463374607431768211456".to_string(), // u128::MAX + 1
            ..Default::default()
        };

        let parsed = req.parse_amount_u256().unwrap();
        assert_eq!(
            parsed.to_string(),
            "340282366920938463463374607431768211456"
        );
    }

    #[test]
    fn test_with_base_units() {
        let req = ChargeRequest {
            amount: "1.5".to_string(),
            currency: "0x123".to_string(),
            decimals: Some(6),
            ..Default::default()
        };
        let converted = req.with_base_units().unwrap();
        assert_eq!(converted.amount, "1500000");
        assert!(converted.decimals.is_none());
    }

    #[test]
    fn test_with_base_units_no_decimals() {
        let req = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "0x123".to_string(),
            ..Default::default()
        };
        let converted = req.with_base_units().unwrap();
        assert_eq!(converted.amount, "1000000");
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
