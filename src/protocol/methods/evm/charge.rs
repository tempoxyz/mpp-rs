//! EVM extensions for ChargeRequest.
//!
//! Provides typed accessors for ChargeRequest when used with EVM-based methods.

use alloy::primitives::{Address, U256};

use super::helpers::{parse_address, parse_amount};
use super::types::EvmMethodDetails;
use crate::error::{MppError, Result};
use crate::protocol::intents::ChargeRequest;

/// Extension trait for ChargeRequest with EVM-specific accessors.
///
/// This provides the minimal common functionality for all EVM chains.
/// Chain-specific extensions (like Tempo's `fee_payer()`) are in their
/// respective method modules.
///
/// # Examples
///
/// ```ignore
/// use mpp_rs::protocol::intents::ChargeRequest;
/// use mpp_rs::protocol::methods::evm::EvmChargeExt;
///
/// let req = ChargeRequest { amount: "1000000".to_string(), ... };
/// let amount: U256 = req.amount_u256()?;
/// let recipient: Address = req.recipient_address()?;
/// ```
pub trait EvmChargeExt {
    /// Get the amount as a typed U256.
    fn amount_u256(&self) -> Result<U256>;

    /// Get the recipient address as a typed Address.
    ///
    /// Returns an error if no recipient is specified or if it's invalid.
    fn recipient_address(&self) -> Result<Address>;

    /// Get the currency/asset address as a typed Address.
    fn currency_address(&self) -> Result<Address>;

    /// Parse the method_details as EVM-specific details.
    fn evm_method_details(&self) -> Result<EvmMethodDetails>;

    /// Get chain ID from methodDetails.
    fn chain_id(&self) -> Option<u64>;
}

impl EvmChargeExt for ChargeRequest {
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

    fn evm_method_details(&self) -> Result<EvmMethodDetails> {
        match &self.method_details {
            Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
                MppError::InvalidChallenge(format!("Invalid EVM method details: {}", e))
            }),
            None => Ok(EvmMethodDetails::default()),
        }
    }

    fn chain_id(&self) -> Option<u64> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("chainId"))
            .and_then(|v| v.as_u64())
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
                "chainId": 1
            })),
        }
    }

    #[test]
    fn test_amount_u256() {
        let req = test_charge_request();
        let amount = req.amount_u256().unwrap();
        assert_eq!(amount, U256::from(1_000_000u64));
    }

    #[test]
    fn test_recipient_address() {
        let req = test_charge_request();
        let addr = req.recipient_address().unwrap();
        assert_eq!(
            format!("{:?}", addr).to_lowercase(),
            "0x742d35cc6634c0532925a3b844bc9e7595f1b0f2"
        );
    }

    #[test]
    fn test_currency_address() {
        let req = test_charge_request();
        let addr = req.currency_address().unwrap();
        assert_eq!(
            format!("{:?}", addr).to_lowercase(),
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        );
    }

    #[test]
    fn test_evm_method_details() {
        let req = test_charge_request();
        let details = req.evm_method_details().unwrap();
        assert_eq!(details.chain_id, Some(1));
    }

    #[test]
    fn test_chain_id() {
        let req = test_charge_request();
        assert_eq!(req.chain_id(), Some(1));
    }

    #[test]
    fn test_no_recipient() {
        let req = ChargeRequest {
            recipient: None,
            ..test_charge_request()
        };
        assert!(req.recipient_address().is_err());
    }
}
