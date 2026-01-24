//! Authorize intent request type.
//!
//! The authorize intent represents a pre-authorization for future payments.
//! This is typically used for subscription setups or spending limits.

use serde::{Deserialize, Serialize};

/// Authorize request (for authorize intent).
///
/// Represents a pre-authorization request that grants permission for future
/// payments up to a specified limit. All fields are strings.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::intents::AuthorizeRequest;
///
/// let req = AuthorizeRequest {
///     asset: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
///     destination: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
///     expires: "2025-01-01T00:00:00Z".to_string(),
///     limit: "10000000".to_string(),
///     valid_from: None,
///     fee_payer: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizeRequest {
    /// Token/asset contract address or identifier
    pub asset: String,

    /// Optional specific recipient/destination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,

    /// Authorization expiration (ISO 8601)
    pub expires: String,

    /// Spending limit in base units
    pub limit: String,

    /// Valid from time (ISO 8601, optional)
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,

    /// Whether server pays transaction fees
    #[serde(rename = "feePayer", skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorize_request_serialization() {
        let req = AuthorizeRequest {
            asset: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            destination: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
            expires: "2025-01-01T00:00:00Z".to_string(),
            limit: "10000000".to_string(),
            valid_from: Some("2024-01-01T00:00:00Z".to_string()),
            fee_payer: Some(true),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"asset\":"));
        assert!(json.contains("\"validFrom\":"));
        assert!(json.contains("\"feePayer\":true"));

        let parsed: AuthorizeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.limit, "10000000");
        assert_eq!(parsed.fee_payer, Some(true));
    }

    #[test]
    fn test_authorize_request_minimal() {
        let json = r#"{"asset":"0x123","expires":"2025-01-01T00:00:00Z","limit":"1000"}"#;
        let parsed: AuthorizeRequest = serde_json::from_str(json).unwrap();

        assert_eq!(parsed.asset, "0x123");
        assert!(parsed.destination.is_none());
        assert!(parsed.valid_from.is_none());
        assert!(parsed.fee_payer.is_none());
    }
}
