//! Tempo extensions for ChargeRequest.
//!
//! Provides Tempo-specific accessors for ChargeRequest.

use super::types::{Split, TempoMethodDetails};
use crate::error::{MppError, Result};
use crate::evm::{parse_address, parse_amount, Address, U256};
use crate::protocol::intents::ChargeRequest;

/// Extension trait for ChargeRequest with Tempo-specific accessors.
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::parse_www_authenticate;
/// use mpp::protocol::intents::ChargeRequest;
/// use mpp::protocol::methods::tempo::TempoChargeExt;
///
/// let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiIweDEyMyIsInJlY2lwaWVudCI6IjB4NDU2In0""#;
/// let challenge = parse_www_authenticate(header).unwrap();
/// let req: ChargeRequest = challenge.request.decode().unwrap();
/// assert!(req.chain_id().is_none());
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

    /// Check if fee sponsorship is enabled.
    fn fee_payer(&self) -> bool;

    /// Get the memo from methodDetails, if present.
    fn memo(&self) -> Option<String>;

    /// Check if this request is for Tempo Moderato network.
    fn is_tempo_moderato(&self) -> bool;

    /// Get the splits from methodDetails, if present.
    fn splits(&self) -> Result<Option<Vec<Split>>>;

    /// Get the Tempo network from chain ID, if recognized.
    fn network(&self) -> Option<super::network::TempoNetwork>;
}

impl TempoChargeExt for ChargeRequest {
    fn amount_u256(&self) -> Result<U256> {
        parse_amount(&self.amount)
    }

    fn recipient_address(&self) -> Result<Address> {
        let recipient = self.recipient.as_ref().ok_or_else(|| {
            MppError::invalid_challenge_reason("No recipient specified".to_string())
        })?;
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
                MppError::invalid_challenge_reason(format!("Invalid Tempo method details: {}", e))
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

    fn memo(&self) -> Option<String> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("memo"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    fn is_tempo_moderato(&self) -> bool {
        self.chain_id() == Some(super::MODERATO_CHAIN_ID)
    }

    fn splits(&self) -> Result<Option<Vec<Split>>> {
        Ok(self.tempo_method_details()?.splits)
    }

    fn network(&self) -> Option<super::network::TempoNetwork> {
        self.chain_id()
            .and_then(super::network::TempoNetwork::from_chain_id)
    }
}

fn parse_memo_bytes_in_context(memo: Option<&str>, context: &str) -> Result<Option<[u8; 32]>> {
    let Some(memo) = memo else {
        return Ok(None);
    };
    if memo.is_empty() {
        return Ok(None);
    }

    let hex_str = memo.strip_prefix("0x").unwrap_or(memo);
    let bytes = hex::decode(hex_str)
        .map_err(|e| MppError::invalid_challenge_reason(format!("Invalid {context}: {e}")))?;

    if bytes.len() != 32 {
        return Err(MppError::invalid_challenge_reason(format!(
            "Invalid {context}: expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Some(arr))
}

/// Parse a hex-encoded memo string to a 32-byte array.
///
/// Returns `None` if the input is `None`, not valid hex, or not exactly 32 bytes.
pub fn parse_memo_bytes(memo: Option<String>) -> Option<[u8; 32]> {
    parse_memo_bytes_checked(memo.as_deref()).ok().flatten()
}

pub(crate) fn parse_memo_bytes_checked(memo: Option<&str>) -> Result<Option<[u8; 32]>> {
    parse_memo_bytes_in_context(memo, "memo")
}

pub(crate) fn parse_split_memo_bytes(memo: Option<&str>) -> Result<Option<[u8; 32]>> {
    parse_memo_bytes_in_context(memo, "split memo")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_charge_request() -> ChargeRequest {
        ChargeRequest {
            amount: "1000000".to_string(),
            currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
            description: None,
            external_id: None,
            method_details: Some(serde_json::json!({
                "chainId": 42431,
                "feePayer": true
            })),
            ..Default::default()
        }
    }

    #[test]
    fn test_tempo_method_details() {
        let req = test_charge_request();
        let details = req.tempo_method_details().unwrap();
        assert_eq!(details.chain_id, Some(42431));
        assert!(details.fee_payer());
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
    fn test_memo() {
        let req = test_charge_request();
        assert!(req.memo().is_none());

        let req_with_memo = ChargeRequest {
            method_details: Some(serde_json::json!({
                "chainId": 42431,
                "memo": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            })),
            ..test_charge_request()
        };
        assert_eq!(
            req_with_memo.memo(),
            Some("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string())
        );

        let req_with_empty_memo = ChargeRequest {
            method_details: Some(serde_json::json!({
                "chainId": 42431,
                "memo": ""
            })),
            ..test_charge_request()
        };
        assert!(req_with_empty_memo.memo().is_none());
    }

    #[test]
    fn test_parse_memo_bytes_checked_treats_empty_as_none() {
        assert!(parse_memo_bytes_checked(Some("")).unwrap().is_none());
    }

    #[test]
    fn test_network_moderato() {
        use crate::protocol::methods::tempo::network::TempoNetwork;
        let req = test_charge_request();
        let network = req.network();
        assert_eq!(network, Some(TempoNetwork::Moderato));
    }

    #[test]
    fn test_network_none() {
        let req = ChargeRequest {
            method_details: Some(serde_json::json!({"chainId": 1})),
            ..test_charge_request()
        };
        assert!(req.network().is_none());
    }

    #[test]
    fn test_parse_memo_bytes_valid() {
        let memo =
            Some("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string());
        let result = parse_memo_bytes(memo);
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0], 0x12);
        assert_eq!(result.unwrap()[31], 0xef);
    }

    #[test]
    fn test_parse_memo_bytes_without_prefix() {
        let memo =
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string());
        assert!(parse_memo_bytes(memo).is_some());
    }

    #[test]
    fn test_parse_memo_bytes_none() {
        assert!(parse_memo_bytes(None).is_none());
    }

    #[test]
    fn test_parse_memo_bytes_wrong_length() {
        let memo = Some("0x1234".to_string());
        assert!(parse_memo_bytes(memo).is_none());
    }

    #[test]
    fn test_parse_memo_bytes_invalid_hex() {
        let memo = Some("0xnotvalidhex".to_string());
        assert!(parse_memo_bytes(memo).is_none());
    }

    #[test]
    fn test_splits() {
        let req = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "0x123".to_string(),
            method_details: Some(serde_json::json!({
                "splits": [
                    {"amount": "300000", "recipient": "0x111", "memo": "0xabcd"},
                    {"amount": "200000", "recipient": "0x222"}
                ]
            })),
            ..Default::default()
        };

        let splits = req.splits().unwrap().unwrap();
        assert_eq!(splits.len(), 2);
        assert_eq!(splits[0].amount, "300000");
        assert_eq!(splits[1].recipient, "0x222");
    }

    #[test]
    fn test_splits_none() {
        let req = test_charge_request();
        assert!(req.splits().unwrap().is_none());
    }

    #[test]
    fn test_splits_empty() {
        let req = ChargeRequest {
            method_details: Some(serde_json::json!({"splits": []})),
            ..test_charge_request()
        };
        let splits = req.splits().unwrap().unwrap();
        assert!(splits.is_empty());
    }

    #[test]
    fn test_splits_rejects_malformed_json() {
        let req = ChargeRequest {
            method_details: Some(serde_json::json!({
                "splits": [{"amount": 1, "recipient": "0x111"}]
            })),
            ..test_charge_request()
        };

        let error = req.splits().unwrap_err();
        assert!(error.to_string().contains("Invalid Tempo method details"));
    }

    #[test]
    fn test_parse_memo_bytes_checked_invalid_hex() {
        let error = parse_memo_bytes_checked(Some("0xnotvalidhex")).unwrap_err();
        assert!(error.to_string().contains("Invalid memo"));
    }

    #[test]
    fn test_parse_split_memo_bytes_wrong_length() {
        let error = parse_split_memo_bytes(Some("0x1234")).unwrap_err();
        assert!(error.to_string().contains("Invalid split memo"));
    }
}
