//! Subscription intent request type.
//!
//! The subscription intent represents a recurring periodic payment request.
//! This module provides the `SubscriptionRequest` type with string-only fields -
//! no typed helpers like `amount_u256()`. Those are provided by the methods layer.

use serde::{Deserialize, Serialize};

use crate::error::{MppError, Result};

/// Subscription request (for subscription intent).
///
/// Represents a recurring periodic payment request. All fields are strings
/// to remain method-agnostic. Use the methods layer for typed accessors.
///
/// # Examples
///
/// ```
/// use mpp::protocol::intents::SubscriptionRequest;
///
/// let req = SubscriptionRequest {
///     amount: "1000000".to_string(),
///     currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
///     interval: "monthly".to_string(),
///     recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
///     description: Some("Pro plan subscription".to_string()),
///     expires: None,
///     external_id: None,
///     billing_cycles: Some(12),
///     trial_period: Some("14d".to_string()),
///     method_details: None,
/// };
///
/// assert_eq!(req.amount, "1000000");
/// assert_eq!(req.interval, "monthly");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriptionRequest {
    /// Amount per billing cycle in base units (e.g., wei, satoshi, cents)
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

    /// Billing interval (e.g., "daily", "weekly", "monthly", "yearly")
    pub interval: String,

    /// Number of billing cycles (None = indefinite)
    #[serde(rename = "billingCycles", skip_serializing_if = "Option::is_none")]
    pub billing_cycles: Option<u32>,

    /// Trial period duration (e.g., "14d", "1m")
    #[serde(rename = "trialPeriod", skip_serializing_if = "Option::is_none")]
    pub trial_period: Option<String>,

    /// Method-specific extension fields (interpreted by methods layer)
    #[serde(rename = "methodDetails", skip_serializing_if = "Option::is_none")]
    pub method_details: Option<serde_json::Value>,
}

impl SubscriptionRequest {
    /// Parse the amount as u128.
    ///
    /// Returns an error if the amount is not a valid unsigned integer.
    pub fn parse_amount(&self) -> Result<u128> {
        self.amount
            .parse()
            .map_err(|_| MppError::InvalidAmount(format!("Invalid amount: {}", self.amount)))
    }

    /// Validate that the subscription amount does not exceed a maximum.
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
    fn test_subscription_request_serialization() {
        let req = SubscriptionRequest {
            amount: "10000".to_string(),
            currency: "0x123".to_string(),
            interval: "monthly".to_string(),
            recipient: Some("0x456".to_string()),
            description: Some("Pro plan".to_string()),
            expires: Some("2024-01-01T00:00:00Z".to_string()),
            external_id: None,
            billing_cycles: Some(12),
            trial_period: Some("14d".to_string()),
            method_details: Some(serde_json::json!({
                "chainId": 42431,
                "feePayer": true
            })),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"amount\":\"10000\""));
        assert!(json.contains("\"interval\":\"monthly\""));
        assert!(json.contains("\"billingCycles\":12"));
        assert!(json.contains("\"trialPeriod\":\"14d\""));
        assert!(json.contains("\"methodDetails\""));
        assert!(json.contains("\"chainId\":42431"));

        let parsed: SubscriptionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.amount, "10000");
        assert_eq!(parsed.interval, "monthly");
        assert_eq!(parsed.billing_cycles, Some(12));
    }

    #[test]
    fn test_subscription_request_optional_fields_omitted() {
        let req = SubscriptionRequest {
            amount: "500".to_string(),
            currency: "USD".to_string(),
            interval: "weekly".to_string(),
            ..Default::default()
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("recipient"));
        assert!(!json.contains("description"));
        assert!(!json.contains("expires"));
        assert!(!json.contains("externalId"));
        assert!(!json.contains("billingCycles"));
        assert!(!json.contains("trialPeriod"));
        assert!(!json.contains("methodDetails"));
    }

    #[test]
    fn test_subscription_request_deserialization() {
        let json = r#"{"amount":"2000","currency":"0xabc","interval":"daily","billingCycles":30}"#;
        let parsed: SubscriptionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.amount, "2000");
        assert_eq!(parsed.currency, "0xabc");
        assert_eq!(parsed.interval, "daily");
        assert_eq!(parsed.billing_cycles, Some(30));
        assert!(parsed.recipient.is_none());
        assert!(parsed.trial_period.is_none());
        assert!(parsed.method_details.is_none());
    }

    #[test]
    fn test_parse_amount() {
        let req = SubscriptionRequest {
            amount: "1000000".to_string(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 1_000_000u128);

        let invalid = SubscriptionRequest {
            amount: "not-a-number".to_string(),
            ..Default::default()
        };
        assert!(invalid.parse_amount().is_err());
    }

    #[test]
    fn test_validate_max_amount() {
        let req = SubscriptionRequest {
            amount: "1000".to_string(),
            ..Default::default()
        };

        assert!(req.validate_max_amount("2000").is_ok());
        assert!(req.validate_max_amount("1000").is_ok());
        assert!(req.validate_max_amount("500").is_err());
    }
}
