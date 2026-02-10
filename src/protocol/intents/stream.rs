//! Stream intent request type.
//!
//! The stream intent represents a streaming/metered payment request where the
//! client pays per unit of usage through a payment channel. This module provides
//! the `StreamRequest` type with string-only fields - no typed helpers like
//! `amount_u256()`. Those are provided by the methods layer (e.g., `methods::tempo::stream`).

use serde::{Deserialize, Serialize};

use crate::error::{MppError, Result};

/// Stream request (for stream intent).
///
/// Represents a metered/streaming payment request where the client pays per unit
/// of usage. All fields are strings to remain method-agnostic. Use the methods
/// layer for typed accessors.
///
/// # Examples
///
/// ```
/// use mpay::protocol::intents::StreamRequest;
///
/// let req = StreamRequest {
///     amount: "1000".to_string(),
///     unit_type: "llm_token".to_string(),
///     currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
///     recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
///     suggested_deposit: Some("100000".to_string()),
///     method_details: None,
/// };
///
/// assert_eq!(req.amount, "1000");
/// assert_eq!(req.unit_type, "llm_token");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StreamRequest {
    /// Amount per unit in base units (e.g., wei per token)
    pub amount: String,

    /// Type of usage unit (e.g., "llm_token", "request")
    #[serde(rename = "unitType")]
    pub unit_type: String,

    /// Currency/asset identifier (token address, ISO 4217 code, or symbol)
    pub currency: String,

    /// Recipient address (optional, server may be recipient)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// Suggested initial deposit amount in base units
    #[serde(rename = "suggestedDeposit", skip_serializing_if = "Option::is_none")]
    pub suggested_deposit: Option<String>,

    /// Method-specific extension fields (interpreted by methods layer)
    #[serde(rename = "methodDetails", skip_serializing_if = "Option::is_none")]
    pub method_details: Option<serde_json::Value>,
}

impl StreamRequest {
    /// Parse the amount as u128.
    ///
    /// Returns an error if the amount is not a valid unsigned integer.
    pub fn parse_amount(&self) -> Result<u128> {
        self.amount
            .parse()
            .map_err(|_| MppError::InvalidAmount(format!("Invalid amount: {}", self.amount)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_request_serialization() {
        let req = StreamRequest {
            amount: "1000".to_string(),
            unit_type: "llm_token".to_string(),
            currency: "0x123".to_string(),
            recipient: Some("0x456".to_string()),
            suggested_deposit: Some("100000".to_string()),
            method_details: Some(serde_json::json!({
                "escrowContract": "0x789",
                "chainId": 42431,
                "feePayer": true
            })),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"amount\":\"1000\""));
        assert!(json.contains("\"unitType\":\"llm_token\""));
        assert!(json.contains("\"suggestedDeposit\":\"100000\""));
        assert!(json.contains("\"methodDetails\""));
        assert!(json.contains("\"escrowContract\":\"0x789\""));

        let parsed: StreamRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.amount, "1000");
        assert_eq!(parsed.unit_type, "llm_token");
        assert_eq!(parsed.suggested_deposit, Some("100000".to_string()));
    }

    #[test]
    fn test_stream_request_optional_fields_omitted() {
        let req = StreamRequest {
            amount: "500".to_string(),
            unit_type: "request".to_string(),
            currency: "0xabc".to_string(),
            recipient: None,
            suggested_deposit: None,
            method_details: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("recipient"));
        assert!(!json.contains("suggestedDeposit"));
        assert!(!json.contains("methodDetails"));
    }

    #[test]
    fn test_parse_amount() {
        let req = StreamRequest {
            amount: "1000000".to_string(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 1_000_000u128);

        let invalid = StreamRequest {
            amount: "not-a-number".to_string(),
            ..Default::default()
        };
        assert!(invalid.parse_amount().is_err());
    }
}
