//! Core types for streaming payment channels.
//!
//! These types represent the data structures used in the stream payment protocol:
//! vouchers, credential payloads, and receipts.

use alloy::primitives::{Bytes, FixedBytes};
use serde::{Deserialize, Serialize};

/// A voucher for cumulative payment.
///
/// Cumulative monotonicity prevents replay attacks — each voucher's
/// `cumulative_amount` must be >= the previous voucher's amount.
#[derive(Debug, Clone)]
pub struct Voucher {
    /// The channel this voucher applies to.
    pub channel_id: FixedBytes<32>,
    /// Cumulative amount authorized (monotonically increasing).
    pub cumulative_amount: u128,
}

/// A signed voucher with EIP-712 signature.
#[derive(Debug, Clone)]
pub struct SignedVoucher {
    /// The channel this voucher applies to.
    pub channel_id: FixedBytes<32>,
    /// Cumulative amount authorized.
    pub cumulative_amount: u128,
    /// EIP-712 signature (65 bytes: r + s + v).
    pub signature: Bytes,
}

/// Stream credential payload — discriminated union on `action`.
///
/// This is the payload inside a `PaymentCredential` for stream intents.
/// The `action` field determines which variant is used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum StreamCredentialPayload {
    /// Open a new payment channel with an initial voucher.
    #[serde(rename = "open")]
    Open {
        /// Always "transaction".
        #[serde(rename = "type")]
        payload_type: String,
        /// Channel identifier (bytes32 hex).
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Signed transaction containing approve + open calls.
        transaction: String,
        /// EIP-712 voucher signature.
        signature: String,
        /// Optional authorized signer address (defaults to payer if zero).
        #[serde(rename = "authorizedSigner", skip_serializing_if = "Option::is_none")]
        authorized_signer: Option<String>,
        /// Initial cumulative amount.
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
    },

    /// Top up an existing channel with additional deposit.
    #[serde(rename = "topUp")]
    TopUp {
        /// Always "transaction".
        #[serde(rename = "type")]
        payload_type: String,
        /// Channel identifier.
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Signed transaction containing approve + topUp calls.
        transaction: String,
        /// Amount being added to the channel deposit.
        #[serde(rename = "additionalDeposit")]
        additional_deposit: String,
    },

    /// Submit an incremental voucher to authorize more spending.
    #[serde(rename = "voucher")]
    Voucher {
        /// Channel identifier.
        #[serde(rename = "channelId")]
        channel_id: String,
        /// New cumulative amount (must be > previous).
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
        /// EIP-712 voucher signature.
        signature: String,
    },

    /// Close the channel with a final voucher.
    #[serde(rename = "close")]
    Close {
        /// Channel identifier.
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Final cumulative amount (must be >= highest accepted).
        #[serde(rename = "cumulativeAmount")]
        cumulative_amount: String,
        /// EIP-712 voucher signature.
        signature: String,
    },
}

/// Stream credential from client (sent in Authorization header).
///
/// Parallels [`PaymentCredential`](crate::protocol::core::PaymentCredential) but uses
/// [`StreamCredentialPayload`] as the payload type, since stream credentials use
/// action-discriminated payloads (voucher, open, topUp, close) rather than
/// the transaction/hash payloads used by charge intents.
///
/// # Examples
///
/// ```
/// use mpay::protocol::core::{PaymentChallenge, Base64UrlJson};
/// use mpay::protocol::methods::tempo::stream::types::{StreamCredential, StreamCredentialPayload};
///
/// # let challenge = PaymentChallenge {
/// #     id: "abc".into(), realm: "api".into(), method: "tempo".into(),
/// #     intent: "stream".into(),
/// #     request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
/// #     expires: None, description: None, digest: None,
/// # };
/// let credential = StreamCredential::voucher(
///     challenge.to_echo(),
///     "0x0000000000000000000000000000000000000000000000000000000000000001",
///     "5000000",
///     "0xsig",
/// );
/// assert!(matches!(credential.payload, StreamCredentialPayload::Voucher { .. }));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCredential {
    /// Echo of challenge parameters from server.
    pub challenge: crate::protocol::core::ChallengeEcho,

    /// Payer identifier (DID format: did:pkh:eip155:chainId:address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Stream-specific payload (action-discriminated).
    pub payload: StreamCredentialPayload,
}

impl StreamCredential {
    /// Create a new stream credential.
    pub fn new(
        challenge: crate::protocol::core::ChallengeEcho,
        payload: StreamCredentialPayload,
    ) -> Self {
        Self {
            challenge,
            source: None,
            payload,
        }
    }

    /// Create a new stream credential with a source DID.
    pub fn with_source(
        challenge: crate::protocol::core::ChallengeEcho,
        source: impl Into<String>,
        payload: StreamCredentialPayload,
    ) -> Self {
        Self {
            challenge,
            source: Some(source.into()),
            payload,
        }
    }

    /// Create a voucher credential for submitting an incremental voucher.
    pub fn voucher(
        challenge: crate::protocol::core::ChallengeEcho,
        channel_id: &str,
        cumulative_amount: &str,
        signature: &str,
    ) -> Self {
        Self::new(
            challenge,
            StreamCredentialPayload::Voucher {
                channel_id: channel_id.to_string(),
                cumulative_amount: cumulative_amount.to_string(),
                signature: signature.to_string(),
            },
        )
    }

    /// Create a close credential for closing a channel with a final voucher.
    pub fn close(
        challenge: crate::protocol::core::ChallengeEcho,
        channel_id: &str,
        cumulative_amount: &str,
        signature: &str,
    ) -> Self {
        Self::new(
            challenge,
            StreamCredentialPayload::Close {
                channel_id: channel_id.to_string(),
                cumulative_amount: cumulative_amount.to_string(),
                signature: signature.to_string(),
            },
        )
    }

    /// Format as an Authorization header value (`Payment <base64url-json>`).
    pub fn to_header(&self) -> crate::error::Result<String> {
        let json = serde_json::to_string(self)?;
        let encoded = crate::protocol::core::base64url_encode(json.as_bytes());
        Ok(format!("Payment {}", encoded))
    }
}

/// Stream receipt returned in the Payment-Receipt header.
///
/// Extends the base receipt contract with stream-specific fields
/// like `channel_id`, `accepted_cumulative`, and `spent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamReceipt {
    /// Payment method ("tempo").
    pub method: String,
    /// Payment intent ("stream").
    pub intent: String,
    /// Receipt status ("success").
    pub status: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Payment reference (channelId). Satisfies the Receipt contract.
    pub reference: String,
    /// Challenge ID this receipt corresponds to.
    pub challenge_id: String,
    /// Channel identifier.
    pub channel_id: String,
    /// Server-accepted cumulative amount.
    pub accepted_cumulative: String,
    /// Amount deducted from the session.
    pub spent: String,
    /// Number of charges in this session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<u64>,
    /// Transaction hash if an on-chain operation was performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_credential_payload_open_serde() {
        let payload = StreamCredentialPayload::Open {
            payload_type: "transaction".to_string(),
            channel_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            transaction: "0xsignedtx".to_string(),
            signature: "0xsig".to_string(),
            authorized_signer: Some("0xsigner".to_string()),
            cumulative_amount: "1000000".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"open\""));
        assert!(json.contains("\"type\":\"transaction\""));
        assert!(json.contains("\"channelId\":"));
        assert!(json.contains("\"cumulativeAmount\":\"1000000\""));
        assert!(json.contains("\"authorizedSigner\":\"0xsigner\""));

        let parsed: StreamCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            StreamCredentialPayload::Open {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "1000000");
            }
            _ => panic!("Expected Open variant"),
        }
    }

    #[test]
    fn test_stream_credential_payload_top_up_serde() {
        let payload = StreamCredentialPayload::TopUp {
            payload_type: "transaction".to_string(),
            channel_id: "0xchannel".to_string(),
            transaction: "0xtx".to_string(),
            additional_deposit: "5000000".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"topUp\""));
        assert!(json.contains("\"additionalDeposit\":\"5000000\""));

        let parsed: StreamCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            StreamCredentialPayload::TopUp {
                additional_deposit, ..
            } => {
                assert_eq!(additional_deposit, "5000000");
            }
            _ => panic!("Expected TopUp variant"),
        }
    }

    #[test]
    fn test_stream_credential_payload_voucher_serde() {
        let payload = StreamCredentialPayload::Voucher {
            channel_id: "0xchannel".to_string(),
            cumulative_amount: "2000000".to_string(),
            signature: "0xsig".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"voucher\""));
        assert!(!json.contains("\"type\"")); // No type field for voucher

        let parsed: StreamCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            StreamCredentialPayload::Voucher {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "2000000");
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[test]
    fn test_stream_credential_payload_close_serde() {
        let payload = StreamCredentialPayload::Close {
            channel_id: "0xchannel".to_string(),
            cumulative_amount: "7000000".to_string(),
            signature: "0xsig".to_string(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"action\":\"close\""));

        let parsed: StreamCredentialPayload = serde_json::from_str(&json).unwrap();
        match parsed {
            StreamCredentialPayload::Close {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "7000000");
            }
            _ => panic!("Expected Close variant"),
        }
    }

    #[test]
    fn test_stream_receipt_serde() {
        let receipt = StreamReceipt {
            method: "tempo".to_string(),
            intent: "stream".to_string(),
            status: "success".to_string(),
            timestamp: "2026-02-07T12:00:00Z".to_string(),
            reference: "0xchannel".to_string(),
            challenge_id: "challenge-1".to_string(),
            channel_id: "0xchannel".to_string(),
            accepted_cumulative: "5000000".to_string(),
            spent: "1000000".to_string(),
            units: Some(3),
            tx_hash: None,
        };

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"acceptedCumulative\":\"5000000\""));
        assert!(json.contains("\"challengeId\":\"challenge-1\""));
        assert!(json.contains("\"units\":3"));
        assert!(!json.contains("txHash"));

        let parsed: StreamReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.accepted_cumulative, "5000000");
        assert_eq!(parsed.units, Some(3));
    }

    #[test]
    fn test_stream_credential_voucher_builder() {
        let echo = crate::protocol::core::ChallengeEcho {
            id: "test-id".to_string(),
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjogdHJ1ZX0".to_string(),
            expires: None,
            digest: None,
        };

        let cred = StreamCredential::voucher(
            echo,
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "5000000",
            "0xsig",
        );

        assert!(cred.source.is_none());
        match &cred.payload {
            StreamCredentialPayload::Voucher {
                channel_id,
                cumulative_amount,
                signature,
            } => {
                assert!(channel_id.starts_with("0x"));
                assert_eq!(cumulative_amount, "5000000");
                assert_eq!(signature, "0xsig");
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[test]
    fn test_stream_credential_close_builder() {
        let echo = crate::protocol::core::ChallengeEcho {
            id: "test-id".to_string(),
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjogdHJ1ZX0".to_string(),
            expires: None,
            digest: None,
        };

        let cred = StreamCredential::close(echo, "0xchannel", "7000000", "0xsig");

        match &cred.payload {
            StreamCredentialPayload::Close {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "7000000");
            }
            _ => panic!("Expected Close variant"),
        }
    }

    #[test]
    fn test_stream_credential_with_source() {
        let echo = crate::protocol::core::ChallengeEcho {
            id: "test-id".to_string(),
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjogdHJ1ZX0".to_string(),
            expires: None,
            digest: None,
        };

        let cred = StreamCredential::with_source(
            echo,
            "did:pkh:eip155:42431:0x1234",
            StreamCredentialPayload::Voucher {
                channel_id: "0xchannel".to_string(),
                cumulative_amount: "1000".to_string(),
                signature: "0xsig".to_string(),
            },
        );

        assert_eq!(cred.source, Some("did:pkh:eip155:42431:0x1234".to_string()));
    }

    #[test]
    fn test_stream_credential_serialization() {
        let echo = crate::protocol::core::ChallengeEcho {
            id: "test-id".to_string(),
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjogdHJ1ZX0".to_string(),
            expires: None,
            digest: None,
        };

        let cred = StreamCredential::voucher(echo, "0xchannel", "5000000", "0xsig");

        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("\"id\":\"test-id\""));
        assert!(json.contains("\"action\":\"voucher\""));
        assert!(json.contains("\"cumulativeAmount\":\"5000000\""));
        let parsed: StreamCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.challenge.id, "test-id");
        match &parsed.payload {
            StreamCredentialPayload::Voucher {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "5000000");
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[test]
    fn test_stream_credential_to_header() {
        let echo = crate::protocol::core::ChallengeEcho {
            id: "test-id".to_string(),
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjogdHJ1ZX0".to_string(),
            expires: None,
            digest: None,
        };

        let cred = StreamCredential::voucher(echo, "0xchannel", "5000000", "0xsig");
        let header = cred.to_header().unwrap();
        assert!(header.starts_with("Payment "));

        let b64 = header.strip_prefix("Payment ").unwrap();
        let decoded = crate::protocol::core::base64url_decode(b64).unwrap();
        let parsed: StreamCredential = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(parsed.challenge.id, "test-id");
    }

    #[test]
    fn test_stream_receipt_with_tx_hash() {
        let receipt = StreamReceipt {
            method: "tempo".to_string(),
            intent: "stream".to_string(),
            status: "success".to_string(),
            timestamp: "2026-02-07T12:00:00Z".to_string(),
            reference: "0xchannel".to_string(),
            challenge_id: "c1".to_string(),
            channel_id: "0xchannel".to_string(),
            accepted_cumulative: "1000000".to_string(),
            spent: "0".to_string(),
            units: None,
            tx_hash: Some("0xdeadbeef".to_string()),
        };

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"txHash\":\"0xdeadbeef\""));
        assert!(!json.contains("\"units\""));
    }
}
