//! Stream intent request type.
//!
//! The stream intent represents a pay-as-you-go streaming payment request using
//! cumulative vouchers over a payment channel. This module provides the
//! `StreamRequest` type with string-only fields.

use serde::{Deserialize, Serialize};

/// Stream request (for stream intent).
///
/// Represents a streaming payment request for pay-as-you-go metered services.
/// All fields are strings to remain method-agnostic.
///
/// # Examples
///
/// ```
/// use mpay::protocol::intents::StreamRequest;
///
/// let req = StreamRequest {
///     amount: Some("75".to_string()),
///     currency: "0x20c0000000000000000000000000000000000001".to_string(),
///     recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string(),
///     decimals: Some(6),
///     unit_type: Some("token".to_string()),
///     suggested_deposit: Some("10000000".to_string()),
///     method_details: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamRequest {
    /// Per-unit cost in base units (optional, server may set it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,

    /// Currency/asset identifier (token address).
    pub currency: String,

    /// Recipient/payee address.
    pub recipient: String,

    /// Token decimals (e.g., 6 for pathUSD).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u32>,

    /// What a "unit" represents (e.g., "token").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_type: Option<String>,

    /// Suggested initial deposit for auto-managed clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_deposit: Option<String>,

    /// Method-specific extension fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_details: Option<StreamMethodDetails>,
}

/// Tempo-specific method details for stream challenges.
///
/// Included in `StreamRequest.method_details` to convey escrow contract
/// address, channel hints, and other Tempo-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamMethodDetails {
    /// Address of the on-chain escrow contract.
    pub escrow_contract: String,

    /// Hint: existing channel ID for recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    /// Minimum voucher increment the server will accept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_voucher_delta: Option<String>,

    /// Chain ID (e.g., 4217 mainnet, 42431 Moderato).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    /// Whether fee sponsorship is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_request_serialization() {
        let req = StreamRequest {
            amount: Some("75".to_string()),
            currency: "0x20c0000000000000000000000000000000000001".to_string(),
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string(),
            decimals: Some(6),
            unit_type: Some("token".to_string()),
            suggested_deposit: Some("10000000".to_string()),
            method_details: Some(StreamMethodDetails {
                escrow_contract: "0xescrow".to_string(),
                channel_id: None,
                min_voucher_delta: Some("1000".to_string()),
                chain_id: Some(42431),
                fee_payer: Some(true),
            }),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"amount\":\"75\""));
        assert!(json.contains("\"unitType\":\"token\""));
        assert!(json.contains("\"suggestedDeposit\":\"10000000\""));
        assert!(json.contains("\"escrowContract\":\"0xescrow\""));
        assert!(json.contains("\"minVoucherDelta\":\"1000\""));
        assert!(json.contains("\"chainId\":42431"));
        assert!(json.contains("\"feePayer\":true"));

        let parsed: StreamRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.amount, Some("75".to_string()));
        assert_eq!(parsed.decimals, Some(6));
    }

    #[test]
    fn test_stream_request_minimal() {
        let req = StreamRequest {
            currency: "0xtoken".to_string(),
            recipient: "0xrecipient".to_string(),
            ..Default::default()
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("amount"));
        assert!(!json.contains("unitType"));
        assert!(!json.contains("suggestedDeposit"));
        assert!(!json.contains("methodDetails"));
        assert!(json.contains("\"currency\":\"0xtoken\""));
        assert!(json.contains("\"recipient\":\"0xrecipient\""));
    }

    #[test]
    fn test_stream_request_deserialize_without_optionals() {
        let json = r#"{"currency":"0xtoken","recipient":"0xrecipient"}"#;
        let req: StreamRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.currency, "0xtoken");
        assert_eq!(req.recipient, "0xrecipient");
        assert!(req.amount.is_none());
        assert!(req.decimals.is_none());
        assert!(req.unit_type.is_none());
        assert!(req.suggested_deposit.is_none());
        assert!(req.method_details.is_none());
    }

    #[test]
    fn test_stream_method_details_serialization() {
        let details = StreamMethodDetails {
            escrow_contract: "0xescrow".to_string(),
            channel_id: Some("0xchannel".to_string()),
            min_voucher_delta: None,
            chain_id: Some(4217),
            fee_payer: None,
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"escrowContract\":\"0xescrow\""));
        assert!(json.contains("\"channelId\":\"0xchannel\""));
        assert!(!json.contains("minVoucherDelta"));
        assert!(!json.contains("feePayer"));
    }
}
