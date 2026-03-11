//! Tempo extensions for SessionRequest.
//!
//! Provides Tempo-specific accessors and credential payload types for SessionRequest.

use crate::error::{MppError, Result};
use crate::protocol::intents::SessionRequest;
use serde::{Deserialize, Serialize};

/// Custom deserializer that only accepts the literal string "transaction".
fn deserialize_transaction_literal<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s != "transaction" {
        return Err(serde::de::Error::custom(format!(
            "expected \"transaction\", got \"{}\"",
            s
        )));
    }
    Ok(s)
}

/// Tempo session-specific method details.
///
/// Extension fields for the `methodDetails` in a session challenge.
///
/// # Examples
///
/// ```
/// use mpp::protocol::methods::tempo::session::TempoSessionMethodDetails;
///
/// let details = TempoSessionMethodDetails {
///     escrow_contract: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
///     channel_id: None,
///     min_voucher_delta: Some("1000".to_string()),
///     chain_id: Some(42431),
///     fee_payer: Some(true),
/// };
/// assert_eq!(details.escrow_contract, "0x1234567890abcdef1234567890abcdef12345678");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempoSessionMethodDetails {
    pub escrow_contract: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_voucher_delta: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,
}

/// Session credential payload, discriminated on the `action` field.
///
/// Each variant corresponds to a session lifecycle action:
/// - `Open`: open a new payment channel (with on-chain transaction)
/// - `TopUp`: add funds to an existing channel (with on-chain transaction)
/// - `Voucher`: off-chain payment voucher
/// - `Close`: close the channel
///
/// # Examples
///
/// ```
/// use mpp::protocol::methods::tempo::session::SessionCredentialPayload;
///
/// let json = r#"{"action":"voucher","channelId":"0xabc","cumulativeAmount":"5000","signature":"0xdef"}"#;
/// let payload: SessionCredentialPayload = serde_json::from_str(json).unwrap();
/// assert!(matches!(payload, SessionCredentialPayload::Voucher { .. }));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum SessionCredentialPayload {
    #[serde(rename = "open")]
    Open {
        #[serde(rename = "type", deserialize_with = "deserialize_transaction_literal")]
        payload_type: String,
        #[serde(rename = "channelId")]
        channel_id: String,
        transaction: String,
        #[serde(rename = "authorizedSigner", skip_serializing_if = "Option::is_none")]
        authorized_signer: Option<String>,
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
        signature: String,
    },
    #[serde(rename = "topUp")]
    TopUp {
        #[serde(rename = "type", deserialize_with = "deserialize_transaction_literal")]
        payload_type: String,
        #[serde(rename = "channelId")]
        channel_id: String,
        transaction: String,
        #[serde(rename = "additionalDeposit")]
        additional_deposit: String,
    },
    #[serde(rename = "voucher")]
    Voucher {
        #[serde(rename = "channelId")]
        channel_id: String,
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
        signature: String,
    },
    #[serde(rename = "close")]
    Close {
        #[serde(rename = "channelId")]
        channel_id: String,
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
        signature: String,
    },
}

/// Extension trait for SessionRequest with Tempo-specific accessors.
///
/// # Examples
///
/// ```
/// use mpp::protocol::intents::SessionRequest;
/// use mpp::protocol::methods::tempo::session::TempoSessionExt;
///
/// let req = SessionRequest {
///     amount: "1000".to_string(),
///     unit_type: Some("second".to_string()),
///     currency: "0x123".to_string(),
///     method_details: Some(serde_json::json!({
///         "escrowContract": "0xescrow",
///         "channelId": "0xchannel",
///         "feePayer": true
///     })),
///     ..Default::default()
/// };
/// assert_eq!(req.escrow_contract().unwrap(), "0xescrow");
/// assert_eq!(req.channel_id(), Some("0xchannel".to_string()));
/// assert!(req.fee_payer());
/// ```
pub trait TempoSessionExt {
    /// Get the escrow contract address from methodDetails.
    fn escrow_contract(&self) -> Result<String>;

    /// Get the channel ID from methodDetails, if present.
    fn channel_id(&self) -> Option<String>;

    /// Get the minimum voucher delta from methodDetails, if present.
    fn min_voucher_delta(&self) -> Option<String>;

    /// Get chain ID from methodDetails.
    fn chain_id(&self) -> Option<u64>;

    /// Check if fee sponsorship is enabled.
    fn fee_payer(&self) -> bool;

    /// Parse the method_details as Tempo session-specific details.
    fn tempo_session_details(&self) -> Result<TempoSessionMethodDetails>;

    /// Get the Tempo network from chain ID, if recognized.
    fn network(&self) -> Option<crate::protocol::methods::tempo::network::TempoNetwork>;
}

impl TempoSessionExt for SessionRequest {
    fn escrow_contract(&self) -> Result<String> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("escrowContract"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                MppError::invalid_challenge_reason(
                    "Missing escrowContract in methodDetails".to_string(),
                )
            })
    }

    fn channel_id(&self) -> Option<String> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("channelId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    fn min_voucher_delta(&self) -> Option<String> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("minVoucherDelta"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    fn chain_id(&self) -> Option<u64> {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("chainId"))
            .and_then(|v| v.as_u64())
    }

    fn fee_payer(&self) -> bool {
        self.method_details
            .as_ref()
            .and_then(|v| v.get("feePayer"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    fn tempo_session_details(&self) -> Result<TempoSessionMethodDetails> {
        match &self.method_details {
            Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
                MppError::invalid_challenge_reason(format!(
                    "Invalid Tempo session method details: {}",
                    e
                ))
            }),
            None => Err(MppError::invalid_challenge_reason(
                "Missing methodDetails for session intent".to_string(),
            )),
        }
    }

    fn network(&self) -> Option<crate::protocol::methods::tempo::network::TempoNetwork> {
        self.chain_id()
            .and_then(crate::protocol::methods::tempo::network::TempoNetwork::from_chain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_request() -> SessionRequest {
        SessionRequest {
            amount: "1000".to_string(),
            unit_type: Some("second".to_string()),
            currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
            suggested_deposit: Some("60000".to_string()),
            method_details: Some(serde_json::json!({
                "escrowContract": "0xEscrow1234567890abcdef1234567890abcdef1234",
                "channelId": "0xchannel123",
                "minVoucherDelta": "500",
                "chainId": 42431,
                "feePayer": true
            })),
            ..Default::default()
        }
    }

    // ==================== TempoSessionMethodDetails Tests ====================

    #[test]
    fn test_session_method_details_serialization() {
        let details = TempoSessionMethodDetails {
            escrow_contract: "0xEscrow".to_string(),
            channel_id: Some("0xchannel".to_string()),
            min_voucher_delta: Some("1000".to_string()),
            chain_id: Some(42431),
            fee_payer: Some(true),
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"escrowContract\":\"0xEscrow\""));
        assert!(json.contains("\"channelId\":\"0xchannel\""));
        assert!(json.contains("\"minVoucherDelta\":\"1000\""));
        assert!(json.contains("\"chainId\":42431"));
        assert!(json.contains("\"feePayer\":true"));

        let parsed: TempoSessionMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.escrow_contract, "0xEscrow");
        assert_eq!(parsed.channel_id.as_deref(), Some("0xchannel"));
        assert_eq!(parsed.min_voucher_delta.as_deref(), Some("1000"));
        assert_eq!(parsed.chain_id, Some(42431));
        assert_eq!(parsed.fee_payer, Some(true));
    }

    #[test]
    fn test_session_method_details_optional_fields_omitted() {
        let details = TempoSessionMethodDetails {
            escrow_contract: "0xEscrow".to_string(),
            channel_id: None,
            min_voucher_delta: None,
            chain_id: None,
            fee_payer: None,
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"escrowContract\""));
        assert!(!json.contains("channelId"));
        assert!(!json.contains("minVoucherDelta"));
        assert!(!json.contains("chainId"));
        assert!(!json.contains("feePayer"));
    }

    // ==================== SessionCredentialPayload Tests ====================

    #[test]
    fn test_open_payload_serialization() {
        let payload = SessionCredentialPayload::Open {
            payload_type: "transaction".to_string(),
            channel_id: "0xchannel123".to_string(),
            transaction: "0xtx456".to_string(),
            authorized_signer: Some("0xsigner789".to_string()),
            cumulative_amount: "10000".to_string(),
            signature: "0xsig".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"open\""));
        assert!(json.contains("\"type\":\"transaction\""));
        assert!(json.contains("\"channelId\":\"0xchannel123\""));
        assert!(json.contains("\"transaction\":\"0xtx456\""));
        assert!(json.contains("\"authorizedSigner\":\"0xsigner789\""));
        assert!(json.contains("\"cumulativeAmount\":\"10000\""));
        assert!(json.contains("\"signature\":\"0xsig\""));

        let parsed: SessionCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            SessionCredentialPayload::Open {
                payload_type,
                channel_id,
                authorized_signer,
                ..
            } => {
                assert_eq!(payload_type, "transaction");
                assert_eq!(channel_id, "0xchannel123");
                assert_eq!(authorized_signer.as_deref(), Some("0xsigner789"));
            }
            _ => panic!("Expected Open variant"),
        }
    }

    #[test]
    fn test_open_payload_without_authorized_signer() {
        let payload = SessionCredentialPayload::Open {
            payload_type: "transaction".to_string(),
            channel_id: "0xchannel123".to_string(),
            transaction: "0xtx456".to_string(),
            authorized_signer: None,
            cumulative_amount: "10000".to_string(),
            signature: "0xsig".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("authorizedSigner"));

        let parsed: SessionCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            SessionCredentialPayload::Open {
                authorized_signer, ..
            } => {
                assert!(authorized_signer.is_none());
            }
            _ => panic!("Expected Open variant"),
        }
    }

    #[test]
    fn test_topup_payload_serialization() {
        let payload = SessionCredentialPayload::TopUp {
            payload_type: "transaction".to_string(),
            channel_id: "0xchannel123".to_string(),
            transaction: "0xtx789".to_string(),
            additional_deposit: "5000".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"topUp\""));
        assert!(json.contains("\"type\":\"transaction\""));
        assert!(json.contains("\"channelId\":\"0xchannel123\""));
        assert!(json.contains("\"transaction\":\"0xtx789\""));
        assert!(json.contains("\"additionalDeposit\":\"5000\""));

        let parsed: SessionCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            SessionCredentialPayload::TopUp {
                payload_type,
                channel_id,
                additional_deposit,
                ..
            } => {
                assert_eq!(payload_type, "transaction");
                assert_eq!(channel_id, "0xchannel123");
                assert_eq!(additional_deposit, "5000");
            }
            _ => panic!("Expected TopUp variant"),
        }
    }

    #[test]
    fn test_voucher_payload_serialization() {
        let payload = SessionCredentialPayload::Voucher {
            channel_id: "0xchannel123".to_string(),
            cumulative_amount: "15000".to_string(),
            signature: "0xvouchersig".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"voucher\""));
        assert!(json.contains("\"channelId\":\"0xchannel123\""));
        assert!(json.contains("\"cumulativeAmount\":\"15000\""));
        assert!(json.contains("\"signature\":\"0xvouchersig\""));
        // Voucher should NOT have a "type" field
        assert!(!json.contains("\"type\""));

        let parsed: SessionCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            SessionCredentialPayload::Voucher {
                channel_id,
                cumulative_amount,
                signature,
            } => {
                assert_eq!(channel_id, "0xchannel123");
                assert_eq!(cumulative_amount, "15000");
                assert_eq!(signature, "0xvouchersig");
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[test]
    fn test_close_payload_serialization() {
        let payload = SessionCredentialPayload::Close {
            channel_id: "0xchannel123".to_string(),
            cumulative_amount: "20000".to_string(),
            signature: "0xclosesig".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"close\""));
        assert!(json.contains("\"channelId\":\"0xchannel123\""));
        assert!(json.contains("\"cumulativeAmount\":\"20000\""));
        assert!(json.contains("\"signature\":\"0xclosesig\""));

        let parsed: SessionCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            SessionCredentialPayload::Close {
                channel_id,
                cumulative_amount,
                signature,
            } => {
                assert_eq!(channel_id, "0xchannel123");
                assert_eq!(cumulative_amount, "20000");
                assert_eq!(signature, "0xclosesig");
            }
            _ => panic!("Expected Close variant"),
        }
    }

    #[test]
    fn test_payload_deserialization_from_json_string() {
        let open_json = r#"{"action":"open","type":"transaction","channelId":"0xabc","transaction":"0xtx","cumulativeAmount":"100","signature":"0xsig"}"#;
        let parsed: SessionCredentialPayload = serde_json::from_str(open_json).unwrap();
        assert!(matches!(parsed, SessionCredentialPayload::Open { .. }));

        let topup_json = r#"{"action":"topUp","type":"transaction","channelId":"0xabc","transaction":"0xtx","additionalDeposit":"200"}"#;
        let parsed: SessionCredentialPayload = serde_json::from_str(topup_json).unwrap();
        assert!(matches!(parsed, SessionCredentialPayload::TopUp { .. }));

        let voucher_json = r#"{"action":"voucher","channelId":"0xabc","cumulativeAmount":"300","signature":"0xsig"}"#;
        let parsed: SessionCredentialPayload = serde_json::from_str(voucher_json).unwrap();
        assert!(matches!(parsed, SessionCredentialPayload::Voucher { .. }));

        let close_json = r#"{"action":"close","channelId":"0xabc","cumulativeAmount":"400","signature":"0xsig"}"#;
        let parsed: SessionCredentialPayload = serde_json::from_str(close_json).unwrap();
        assert!(matches!(parsed, SessionCredentialPayload::Close { .. }));
    }

    // ==================== TempoSessionExt Tests ====================

    #[test]
    fn test_escrow_contract() {
        let req = test_session_request();
        assert_eq!(
            req.escrow_contract().unwrap(),
            "0xEscrow1234567890abcdef1234567890abcdef1234"
        );
    }

    #[test]
    fn test_escrow_contract_missing() {
        let req = SessionRequest {
            method_details: None,
            ..test_session_request()
        };
        assert!(req.escrow_contract().is_err());
    }

    #[test]
    fn test_channel_id() {
        let req = test_session_request();
        assert_eq!(req.channel_id(), Some("0xchannel123".to_string()));

        let req_no_channel = SessionRequest {
            method_details: Some(serde_json::json!({
                "escrowContract": "0xEscrow"
            })),
            ..test_session_request()
        };
        assert!(req_no_channel.channel_id().is_none());
    }

    #[test]
    fn test_min_voucher_delta() {
        let req = test_session_request();
        assert_eq!(req.min_voucher_delta(), Some("500".to_string()));

        let req_no_delta = SessionRequest {
            method_details: Some(serde_json::json!({
                "escrowContract": "0xEscrow"
            })),
            ..test_session_request()
        };
        assert!(req_no_delta.min_voucher_delta().is_none());
    }

    #[test]
    fn test_chain_id() {
        let req = test_session_request();
        assert_eq!(req.chain_id(), Some(42431));

        let req_no_chain = SessionRequest {
            method_details: Some(serde_json::json!({
                "escrowContract": "0xEscrow"
            })),
            ..test_session_request()
        };
        assert!(req_no_chain.chain_id().is_none());
    }

    #[test]
    fn test_fee_payer() {
        let req = test_session_request();
        assert!(req.fee_payer());

        let req_no_fee = SessionRequest {
            method_details: Some(serde_json::json!({
                "escrowContract": "0xEscrow"
            })),
            ..test_session_request()
        };
        assert!(!req_no_fee.fee_payer());

        let req_no_details = SessionRequest {
            method_details: None,
            ..test_session_request()
        };
        assert!(!req_no_details.fee_payer());
    }

    #[test]
    fn test_tempo_session_details() {
        let req = test_session_request();
        let details = req.tempo_session_details().unwrap();
        assert_eq!(
            details.escrow_contract,
            "0xEscrow1234567890abcdef1234567890abcdef1234"
        );
        assert_eq!(details.channel_id.as_deref(), Some("0xchannel123"));
        assert_eq!(details.min_voucher_delta.as_deref(), Some("500"));
        assert_eq!(details.chain_id, Some(42431));
        assert_eq!(details.fee_payer, Some(true));
    }

    #[test]
    fn test_tempo_session_details_missing() {
        let req = SessionRequest {
            method_details: None,
            ..test_session_request()
        };
        assert!(req.tempo_session_details().is_err());
    }

    #[test]
    fn test_open_payload_rejects_non_transaction_type() {
        let json = r#"{"action":"open","type":"hash","channelId":"0xabc","transaction":"0xtx","cumulativeAmount":"100","signature":"0xsig"}"#;
        let result = serde_json::from_str::<SessionCredentialPayload>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expected \"transaction\""), "error was: {err}");
    }

    #[test]
    fn test_topup_payload_rejects_non_transaction_type() {
        let json = r#"{"action":"topUp","type":"hash","channelId":"0xabc","transaction":"0xtx","additionalDeposit":"200"}"#;
        let result = serde_json::from_str::<SessionCredentialPayload>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expected \"transaction\""), "error was: {err}");
    }

    #[test]
    fn test_network_moderato() {
        let req = test_session_request();
        let network = req.network();
        assert_eq!(
            network,
            Some(crate::protocol::methods::tempo::network::TempoNetwork::Moderato)
        );
    }

    #[test]
    fn test_network_none() {
        let req = SessionRequest {
            method_details: Some(serde_json::json!({
                "escrowContract": "0xEscrow",
                "chainId": 1
            })),
            ..test_session_request()
        };
        assert!(req.network().is_none());
    }
}
