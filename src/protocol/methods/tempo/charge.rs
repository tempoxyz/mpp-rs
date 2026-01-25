//! Tempo extensions for ChargeRequest.
//!
//! Provides Tempo-specific accessors for ChargeRequest, including 2D nonces
//! and TIP-20 fee token support.

use super::types::TempoMethodDetails;
use crate::error::{MppError, Result};
use crate::evm::{parse_address, parse_amount, Address, U256};
use crate::protocol::intents::ChargeRequest;

/// Extension trait for ChargeRequest with Tempo-specific accessors.
///
/// # Examples
///
/// ```
/// use mpay::protocol::core::parse_www_authenticate;
/// use mpay::protocol::intents::ChargeRequest;
/// use mpay::protocol::methods::tempo::TempoChargeExt;
///
/// let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiIweDEyMyIsInJlY2lwaWVudCI6IjB4NDU2In0""#;
/// let challenge = parse_www_authenticate(header).unwrap();
/// let req: ChargeRequest = challenge.request.decode().unwrap();
/// let nonce_key = req.nonce_key();
/// ```
pub trait TempoChargeExt {
    /// Get the amount as a typed U256.
    fn amount_u256(&self) -> Result<U256>;

    /// Get the recipient address as a typed Address.
    fn recipient_address(&self) -> Result<Address>;

    /// Get the currency/asset address as a typed Address.
    fn currency_address(&self) -> Result<Address>;

    /// Get chain ID from methodDetails.
    fn chain_id(&self) -> Option<u64>;

    /// Parse the method_details as Tempo-specific details.
    fn tempo_method_details(&self) -> Result<TempoMethodDetails>;

    /// Check if server pays transaction fees (Tempo-specific feature).
    fn fee_payer(&self) -> bool;

    /// Get the 2D nonce key.
    ///
    /// Returns U256::ZERO if not specified (default nonce stream).
    fn nonce_key(&self) -> U256;

    /// Get the fee token address.
    ///
    /// Returns the fee_token from methodDetails if specified,
    /// otherwise returns the payment currency address.
    fn fee_token(&self) -> Option<String>;

    /// Check if this request is for Tempo Moderato network.
    fn is_tempo_moderato(&self) -> bool;

    /// Get the valid_before timestamp from method details.
    fn valid_before(&self) -> Option<String>;

    /// Get the valid_from timestamp from method details.
    fn valid_from(&self) -> Option<String>;
}

impl TempoChargeExt for ChargeRequest {
    fn amount_u256(&self) -> Result<U256> {
        parse_amount(&self.amount)
    }

    fn recipient_address(&self) -> Result<Address> {
        let recipient = self
            .recipient
            .as_ref()
            .ok_or_else(|| MppError::InvalidChallenge("No recipient specified".to_string()))?;
        parse_address(recipient)
    }

    fn currency_address(&self) -> Result<Address> {
        parse_address(&self.currency)
    }

    fn chain_id(&self) -> Option<u64> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("chainId"))
            .and_then(|v| v.as_u64())
    }

    fn tempo_method_details(&self) -> Result<TempoMethodDetails> {
        match &self.method_details {
            Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
                MppError::InvalidChallenge(format!("Invalid Tempo method details: {}", e))
            }),
            None => Ok(TempoMethodDetails::default()),
        }
    }

    fn fee_payer(&self) -> bool {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("feePayer"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    fn nonce_key(&self) -> U256 {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("nonceKey"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .map(U256::from)
            .unwrap_or(U256::ZERO)
    }

    fn fee_token(&self) -> Option<String> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("feeToken"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    fn is_tempo_moderato(&self) -> bool {
        self.chain_id() == Some(super::CHAIN_ID)
    }

    fn valid_before(&self) -> Option<String> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("validBefore"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    fn valid_from(&self) -> Option<String> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("validFrom"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_charge_request() -> ChargeRequest {
        ChargeRequest {
            amount: "1000000".to_string(),
            currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
            expires: Some("2024-01-01T00:00:00Z".to_string()),
            description: None,
            external_id: None,
            method_details: Some(serde_json::json!({
                "chainId": 88153,
                "feePayer": true,
                "nonceKey": "42",
                "feeToken": "0xDEF",
                "validBefore": "2025-01-01T00:00:00Z"
            })),
        }
    }

    #[test]
    fn test_tempo_method_details() {
        let req = test_charge_request();
        let details = req.tempo_method_details().unwrap();
        assert_eq!(details.chain_id, Some(88153));
        assert!(details.fee_payer());
        assert_eq!(details.nonce_key, Some("42".to_string()));
        assert_eq!(details.fee_token, Some("0xDEF".to_string()));
    }

    #[test]
    fn test_fee_payer() {
        let req = test_charge_request();
        assert!(req.fee_payer());

        let req_no_fee = ChargeRequest {
            method_details: None,
            ..test_charge_request()
        };
        assert!(!req_no_fee.fee_payer());
    }

    #[test]
    fn test_nonce_key() {
        let req = test_charge_request();
        assert_eq!(req.nonce_key(), U256::from(42u64));

        let req_no_nonce = ChargeRequest {
            method_details: None,
            ..test_charge_request()
        };
        assert_eq!(req_no_nonce.nonce_key(), U256::ZERO);
    }

    #[test]
    fn test_fee_token() {
        let req = test_charge_request();
        assert_eq!(req.fee_token(), Some("0xDEF".to_string()));

        let req_no_fee_token = ChargeRequest {
            method_details: Some(serde_json::json!({"chainId": 88153})),
            ..test_charge_request()
        };
        assert_eq!(req_no_fee_token.fee_token(), None);
    }

    #[test]
    fn test_is_tempo_moderato() {
        let req = test_charge_request();
        assert!(req.is_tempo_moderato());

        let req_other_chain = ChargeRequest {
            method_details: Some(serde_json::json!({"chainId": 1})),
            ..test_charge_request()
        };
        assert!(!req_other_chain.is_tempo_moderato());
    }

    #[test]
    fn test_valid_before() {
        let req = test_charge_request();
        assert_eq!(req.valid_before(), Some("2025-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn test_valid_from() {
        let req = ChargeRequest {
            method_details: Some(serde_json::json!({
                "validFrom": "2024-06-01T00:00:00Z"
            })),
            ..test_charge_request()
        };
        assert_eq!(req.valid_from(), Some("2024-06-01T00:00:00Z".to_string()));
    }
}
