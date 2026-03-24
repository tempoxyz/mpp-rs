//! WebSocket transport for server-side session payments.
//!
//! Provides a WebSocket transport that implements [`Transport`](super::transport::Transport)
//! for bidirectional payment flows. Unlike SSE (server→client only), WebSocket
//! allows the client to send vouchers inline without a separate HTTP request.
//!
//! # Message Protocol
//!
//! All messages are JSON-encoded with a `type` discriminator:
//!
//! **Client → Server:**
//! - `{ "type": "credential", "credential": "Payment ..." }` — payment credential
//!
//! **Server → Client:**
//! - `{ "type": "challenge", "challenge": { ... } }` — payment challenge
//! - `{ "type": "message", "data": "..." }` — application data
//! - `{ "type": "need-voucher", ... }` — balance exhausted, send new voucher
//! - `{ "type": "receipt", "receipt": { ... } }` — final payment receipt
//! - `{ "type": "error", "error": "..." }` — error message
//!
//! # Example
//!
//! ```ignore
//! use mpp::server::ws::{WsTransport, WsMessage};
//!
//! let transport = WsTransport;
//!
//! // Parse incoming WS message
//! let msg: WsMessage = serde_json::from_str(&text)?;
//! let credential = transport.get_credential(&msg)?;
//! ```

use serde::{Deserialize, Serialize};

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential, Receipt};

use super::transport::{ChallengeContext, ReceiptContext, Transport};

/// Incoming WebSocket message from client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WsMessage {
    /// Client sends a payment credential.
    Credential {
        /// The serialized credential string (e.g., "Payment id=..., ...").
        credential: String,
    },
    /// Client sends application data.
    #[serde(rename = "message")]
    Data {
        /// Application payload.
        data: serde_json::Value,
    },
}

/// Outgoing WebSocket message from server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WsResponse {
    /// Server issues a payment challenge.
    Challenge {
        /// The payment challenge.
        challenge: serde_json::Value,
        /// Optional error context.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Server sends application data.
    #[serde(rename = "message")]
    Data {
        /// Application payload.
        data: String,
    },
    /// Server signals balance exhausted — client should send a new voucher.
    NeedVoucher {
        /// Channel identifier.
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Minimum cumulative amount required for next voucher.
        #[serde(rename = "requiredCumulative")]
        required_cumulative: String,
        /// Current highest accepted cumulative amount.
        #[serde(rename = "acceptedCumulative")]
        accepted_cumulative: String,
        /// Current on-chain deposit.
        deposit: String,
    },
    /// Server sends final payment receipt.
    Receipt {
        /// The payment receipt.
        receipt: serde_json::Value,
    },
    /// Server sends an error.
    Error {
        /// Error message.
        error: String,
    },
}

impl WsResponse {
    /// Serialize this response to a JSON string for sending over WebSocket.
    pub fn to_text(&self) -> String {
        serde_json::to_string(self).expect("WsResponse serialization cannot fail")
    }
}

/// WebSocket transport for server-side payment handling.
///
/// Messages are JSON-encoded WebSocket text frames with a `type` discriminator.
/// The client sends credentials as `{ "type": "credential", "credential": "Payment ..." }`,
/// and the server responds with challenges, data, and receipts.
pub struct WsTransport;

/// Create a WebSocket transport instance.
pub fn ws() -> WsTransport {
    WsTransport
}

impl Transport for WsTransport {
    type Input = WsMessage;
    type ChallengeOutput = WsResponse;
    type ReceiptOutput = WsResponse;

    fn name(&self) -> &str {
        "ws"
    }

    fn get_credential(&self, input: &Self::Input) -> Result<Option<PaymentCredential>, MppError> {
        match input {
            WsMessage::Credential { credential } => {
                let parsed =
                    crate::protocol::core::parse_authorization(credential).map_err(|e| {
                        MppError::MalformedCredential(Some(format!(
                            "failed to parse WS credential: {e}"
                        )))
                    })?;
                Ok(Some(parsed))
            }
            WsMessage::Data { .. } => Ok(None),
        }
    }

    fn respond_challenge(&self, ctx: ChallengeContext<'_, Self::Input>) -> Self::ChallengeOutput {
        let challenge_json = serde_json::to_value(ctx.challenge)
            .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}));

        WsResponse::Challenge {
            challenge: challenge_json,
            error: ctx.error.map(|s| s.to_string()),
        }
    }

    fn respond_receipt(&self, ctx: ReceiptContext<'_, Self::ReceiptOutput>) -> Self::ReceiptOutput {
        let receipt_json = serde_json::to_value(ctx.receipt)
            .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}));

        WsResponse::Receipt {
            receipt: receipt_json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::Base64UrlJson;

    #[test]
    fn test_ws_transport_name() {
        let transport = ws();
        assert_eq!(transport.name(), "ws");
    }

    #[test]
    fn test_ws_message_credential_serde() {
        let msg = WsMessage::Credential {
            credential: "Payment id=\"abc\"".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"credential\""));
        assert!(json.contains("\"credential\":\"Payment id=\\\"abc\\\"\""));

        let parsed: WsMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            WsMessage::Credential { credential } => {
                assert_eq!(credential, "Payment id=\"abc\"")
            }
            _ => panic!("expected Credential variant"),
        }
    }

    #[test]
    fn test_ws_message_data_serde() {
        let msg = WsMessage::Data {
            data: serde_json::json!({"prompt": "hello"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"message\""));

        let parsed: WsMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, WsMessage::Data { .. }));
    }

    #[test]
    fn test_ws_response_challenge_serde() {
        let resp = WsResponse::Challenge {
            challenge: serde_json::json!({"id": "ch-1", "method": "tempo"}),
            error: None,
        };
        let json = resp.to_text();
        assert!(json.contains("\"type\":\"challenge\""));
        assert!(json.contains("\"ch-1\""));
    }

    #[test]
    fn test_ws_response_need_voucher_serde() {
        let resp = WsResponse::NeedVoucher {
            channel_id: "0xabc".into(),
            required_cumulative: "2000".into(),
            accepted_cumulative: "1000".into(),
            deposit: "5000".into(),
        };
        let json = resp.to_text();
        assert!(json.contains("\"type\":\"needVoucher\""));
        assert!(json.contains("\"channelId\":\"0xabc\""));
    }

    #[test]
    fn test_ws_response_receipt_serde() {
        let resp = WsResponse::Receipt {
            receipt: serde_json::json!({"status": "success", "reference": "0x123"}),
        };
        let json = resp.to_text();
        assert!(json.contains("\"type\":\"receipt\""));
        assert!(json.contains("\"0x123\""));
    }

    #[test]
    fn test_ws_response_error_serde() {
        let resp = WsResponse::Error {
            error: "payment failed".into(),
        };
        let json = resp.to_text();
        assert!(json.contains("\"type\":\"error\""));
        assert!(json.contains("payment failed"));
    }

    #[test]
    fn test_ws_get_credential_none_for_data() {
        let transport = ws();
        let msg = WsMessage::Data {
            data: serde_json::json!({"prompt": "hello"}),
        };
        let result = transport.get_credential(&msg).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_ws_respond_challenge() {
        let transport = ws();
        let challenge = PaymentChallenge::new(
            "test-id",
            "test.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
        );
        let msg = WsMessage::Data {
            data: serde_json::json!({}),
        };

        let resp = transport.respond_challenge(ChallengeContext {
            challenge: &challenge,
            input: &msg,
            error: None,
        });

        match resp {
            WsResponse::Challenge {
                challenge: ch,
                error,
            } => {
                assert!(ch.get("id").is_some());
                assert!(error.is_none());
            }
            _ => panic!("expected Challenge response"),
        }
    }

    #[test]
    fn test_ws_respond_receipt() {
        let transport = ws();
        let receipt = Receipt::success("tempo", "0xabc123");

        // The response input doesn't matter for receipts — it's replaced
        let dummy = WsResponse::Data { data: "ok".into() };

        let resp = transport.respond_receipt(ReceiptContext {
            challenge_id: "ch-1",
            receipt: &receipt,
            response: dummy,
        });

        match resp {
            WsResponse::Receipt { receipt } => {
                assert_eq!(receipt["status"], "success");
                assert_eq!(receipt["reference"], "0xabc123");
            }
            _ => panic!("expected Receipt response"),
        }
    }
}
