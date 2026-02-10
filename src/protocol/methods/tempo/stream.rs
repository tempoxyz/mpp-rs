//! Tempo extensions for StreamRequest.
//!
//! Provides Tempo-specific accessors and types for stream payment channels.

use serde::{Deserialize, Serialize};

use crate::error::{MppError, Result};
use crate::evm::{parse_address, parse_amount, Address, U256};
use crate::protocol::intents::StreamRequest;

/// Tempo stream-specific method details.
///
/// Contains fields specific to the Tempo streaming payment channel flow,
/// including escrow contract address and channel parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempoStreamMethodDetails {
    /// Address of the escrow contract managing the payment channel
    #[serde(rename = "escrowContract")]
    pub escrow_contract: String,

    /// Payment channel ID (hex-encoded)
    #[serde(rename = "channelId", skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    /// Minimum voucher delta amount in base units
    #[serde(rename = "minVoucherDelta", skip_serializing_if = "Option::is_none")]
    pub min_voucher_delta: Option<String>,

    /// Chain ID for the stream
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    /// Whether fee sponsorship is enabled
    #[serde(rename = "feePayer", skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,
}

impl TempoStreamMethodDetails {
    /// Check if fee sponsorship is enabled.
    pub fn fee_payer(&self) -> bool {
        self.fee_payer.unwrap_or(false)
    }

    /// Check if this is for the Tempo Moderato network.
    pub fn is_tempo_moderato(&self) -> bool {
        self.chain_id == Some(super::MODERATO_CHAIN_ID)
    }
}

/// Stream credential payload (discriminated by `action`).
///
/// Represents the different actions a client can take in a streaming payment channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum StreamCredentialPayload {
    /// Open a new payment channel
    Open {
        /// Type of credential (e.g., "transaction")
        #[serde(rename = "type")]
        payload_type: String,
        /// Payment channel ID
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Signed transaction hex
        transaction: String,
        /// Signature hex
        signature: String,
        /// Optional authorized signer address
        #[serde(rename = "authorizedSigner", skip_serializing_if = "Option::is_none")]
        authorized_signer: Option<String>,
        /// Cumulative amount paid through the channel
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
    },
    /// Top up an existing payment channel
    TopUp {
        /// Type of credential (e.g., "transaction")
        #[serde(rename = "type")]
        payload_type: String,
        /// Payment channel ID
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Signed transaction hex
        transaction: String,
        /// Additional deposit amount
        #[serde(rename = "additionalDeposit")]
        additional_deposit: String,
    },
    /// Submit a payment voucher
    Voucher {
        /// Payment channel ID
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Cumulative amount paid through the channel
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
        /// Signature hex
        signature: String,
    },
    /// Close a payment channel
    Close {
        /// Payment channel ID
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Cumulative amount paid through the channel
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
        /// Signature hex
        signature: String,
    },
}

/// Stream payment receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamReceipt {
    /// Payment method (always "tempo")
    pub method: String,
    /// Payment intent (always "stream")
    pub intent: String,
    /// Receipt status
    pub status: String,
    /// Timestamp (ISO 8601)
    pub timestamp: String,
    /// Server reference
    pub reference: String,
    /// Challenge ID
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    /// Payment channel ID
    #[serde(rename = "channelId")]
    pub channel_id: String,
    /// Accepted cumulative amount
    #[serde(rename = "acceptedCumulative")]
    pub accepted_cumulative: String,
    /// Amount spent in this interaction
    pub spent: String,
    /// Number of units consumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<u64>,
    /// Transaction hash (if applicable)
    #[serde(rename = "txHash", skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

/// Extension trait for StreamRequest with Tempo-specific accessors.
pub trait TempoStreamExt {
    /// Get the amount per unit as a typed U256.
    fn amount_u256(&self) -> Result<U256>;

    /// Get the recipient address as a typed Address.
    fn recipient_address(&self) -> Result<Address>;

    /// Get the currency/asset address as a typed Address.
    fn currency_address(&self) -> Result<Address>;

    /// Get chain ID from methodDetails.
    fn chain_id(&self) -> Option<u64>;

    /// Parse the method_details as Tempo stream-specific details.
    fn tempo_stream_method_details(&self) -> Result<TempoStreamMethodDetails>;

    /// Check if fee sponsorship is enabled.
    fn fee_payer(&self) -> bool;

    /// Get the escrow contract address from methodDetails.
    fn escrow_contract(&self) -> Result<String>;

    /// Check if this request is for Tempo Moderato network.
    fn is_tempo_moderato(&self) -> bool;
}

impl TempoStreamExt for StreamRequest {
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

    fn tempo_stream_method_details(&self) -> Result<TempoStreamMethodDetails> {
        match &self.method_details {
            Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
                MppError::invalid_challenge_reason(format!(
                    "Invalid Tempo stream method details: {}",
                    e
                ))
            }),
            None => Err(MppError::invalid_challenge_reason(
                "Stream intent requires methodDetails with escrowContract".to_string(),
            )),
        }
    }

    fn fee_payer(&self) -> bool {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("feePayer"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    fn escrow_contract(&self) -> Result<String> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("escrowContract"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                MppError::invalid_challenge_reason(
                    "Stream intent requires escrowContract in methodDetails".to_string(),
                )
            })
    }

    fn is_tempo_moderato(&self) -> bool {
        self.chain_id() == Some(super::MODERATO_CHAIN_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_stream_request() -> StreamRequest {
        StreamRequest {
            amount: "1000".to_string(),
            unit_type: "llm_token".to_string(),
            currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
            suggested_deposit: Some("100000".to_string()),
            method_details: Some(serde_json::json!({
                "escrowContract": "0x1234567890abcdef1234567890abcdef12345678",
                "chainId": 42431,
                "feePayer": true
            })),
        }
    }

    #[test]
    fn test_tempo_stream_method_details() {
        let req = test_stream_request();
        let details = req.tempo_stream_method_details().unwrap();
        assert_eq!(
            details.escrow_contract,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
        assert_eq!(details.chain_id, Some(42431));
        assert!(details.fee_payer());
        assert!(details.is_tempo_moderato());
    }

    #[test]
    fn test_fee_payer() {
        let req = test_stream_request();
        assert!(req.fee_payer());

        let req_no_fee = StreamRequest {
            method_details: None,
            ..test_stream_request()
        };
        assert!(!req_no_fee.fee_payer());
    }

    #[test]
    fn test_is_tempo_moderato() {
        let req = test_stream_request();
        assert!(req.is_tempo_moderato());

        let req_other_chain = StreamRequest {
            method_details: Some(serde_json::json!({
                "escrowContract": "0x123",
                "chainId": 1
            })),
            ..test_stream_request()
        };
        assert!(!req_other_chain.is_tempo_moderato());
    }

    #[test]
    fn test_escrow_contract() {
        let req = test_stream_request();
        assert_eq!(
            req.escrow_contract().unwrap(),
            "0x1234567890abcdef1234567890abcdef12345678"
        );

        let req_no_details = StreamRequest {
            method_details: None,
            ..test_stream_request()
        };
        assert!(req_no_details.escrow_contract().is_err());
    }

    #[test]
    fn test_stream_credential_payload_open() {
        let payload = StreamCredentialPayload::Open {
            payload_type: "transaction".to_string(),
            channel_id: "0xabc".to_string(),
            transaction: "0xdef".to_string(),
            signature: "0x123".to_string(),
            authorized_signer: Some("0x456".to_string()),
            cumulative_amount: "5000".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"open\""));
        assert!(json.contains("\"type\":\"transaction\""));
        assert!(json.contains("\"channelId\":\"0xabc\""));
        assert!(json.contains("\"authorizedSigner\":\"0x456\""));

        let parsed: StreamCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            StreamCredentialPayload::Open { channel_id, .. } => {
                assert_eq!(channel_id, "0xabc");
            }
            _ => panic!("Expected Open variant"),
        }
    }

    #[test]
    fn test_stream_credential_payload_voucher() {
        let payload = StreamCredentialPayload::Voucher {
            channel_id: "0xabc".to_string(),
            cumulative_amount: "10000".to_string(),
            signature: "0xsig".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"voucher\""));
        assert!(json.contains("\"cumulativeAmount\":\"10000\""));

        let parsed: StreamCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            StreamCredentialPayload::Voucher {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "10000");
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[test]
    fn test_stream_credential_payload_top_up() {
        let payload = StreamCredentialPayload::TopUp {
            payload_type: "transaction".to_string(),
            channel_id: "0xabc".to_string(),
            transaction: "0xdef".to_string(),
            additional_deposit: "50000".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"topUp\""));
        assert!(json.contains("\"additionalDeposit\":\"50000\""));
    }

    #[test]
    fn test_stream_credential_payload_close() {
        let payload = StreamCredentialPayload::Close {
            channel_id: "0xabc".to_string(),
            cumulative_amount: "99000".to_string(),
            signature: "0xsig".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"close\""));
    }

    #[test]
    fn test_stream_receipt_serialization() {
        let receipt = StreamReceipt {
            method: "tempo".to_string(),
            intent: "stream".to_string(),
            status: "success".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            reference: "ref-123".to_string(),
            challenge_id: "ch-456".to_string(),
            channel_id: "0xabc".to_string(),
            accepted_cumulative: "10000".to_string(),
            spent: "5000".to_string(),
            units: Some(100),
            tx_hash: Some("0xdeadbeef".to_string()),
        };

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"challengeId\":\"ch-456\""));
        assert!(json.contains("\"channelId\":\"0xabc\""));
        assert!(json.contains("\"acceptedCumulative\":\"10000\""));
        assert!(json.contains("\"txHash\":\"0xdeadbeef\""));

        let parsed: StreamReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.spent, "5000");
        assert_eq!(parsed.units, Some(100));
    }

    #[test]
    fn test_tempo_stream_method_details_serialization() {
        let details = TempoStreamMethodDetails {
            escrow_contract: "0x789".to_string(),
            channel_id: Some("0xabc".to_string()),
            min_voucher_delta: Some("100".to_string()),
            chain_id: Some(42431),
            fee_payer: Some(true),
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"escrowContract\":\"0x789\""));
        assert!(json.contains("\"channelId\":\"0xabc\""));
        assert!(json.contains("\"minVoucherDelta\":\"100\""));
        assert!(json.contains("\"chainId\":42431"));
        assert!(json.contains("\"feePayer\":true"));

        let parsed: TempoStreamMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.escrow_contract, "0x789");
        assert!(parsed.fee_payer());
        assert!(parsed.is_tempo_moderato());
    }
}
