//! WebSocket transport for client-side session payments.
//!
//! Provides a WebSocket transport that implements [`Transport`](super::transport::Transport)
//! for bidirectional payment flows. The client can send vouchers inline over the
//! same WebSocket connection (no separate HTTP request needed).
//!
//! # Message Protocol
//!
//! Uses the same JSON message format as [`server::ws`](crate::server::ws):
//!
//! **Client → Server:**
//! - `{ "type": "credential", "credential": "Payment ..." }`
//!
//! **Server → Client:**
//! - `{ "type": "challenge", "challenge": { ... } }`
//! - `{ "type": "message", "data": "..." }`
//! - `{ "type": "needVoucher", ... }`
//! - `{ "type": "receipt", ... }`
//!
//! # Example
//!
//! ```ignore
//! use mpp::client::ws::WsTransport;
//! use mpp::client::transport::Transport;
//!
//! let transport = WsTransport;
//! ```

use serde::{Deserialize, Serialize};

use crate::error::MppError;
use crate::protocol::core::PaymentChallenge;

use super::transport::Transport;

/// Outgoing WebSocket message from client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WsClientMessage {
    /// Client sends a payment credential.
    Credential {
        /// The serialized credential string.
        credential: String,
    },
    /// Client sends application data.
    #[serde(rename = "message")]
    Data {
        /// Application payload.
        data: serde_json::Value,
    },
}

impl WsClientMessage {
    /// Serialize this message to a JSON string for sending over WebSocket.
    pub fn to_text(&self) -> String {
        serde_json::to_string(self).expect("WsClientMessage serialization cannot fail")
    }
}

/// Incoming WebSocket message from server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WsServerMessage {
    /// Server issues a payment challenge.
    Challenge {
        /// The payment challenge.
        challenge: serde_json::Value,
        /// Optional error context.
        #[serde(default)]
        error: Option<String>,
    },
    /// Server sends application data.
    #[serde(rename = "message")]
    Data {
        /// Application payload.
        data: String,
    },
    /// Server signals balance exhausted.
    NeedVoucher {
        /// Channel identifier.
        #[serde(rename = "channelId")]
        channel_id: String,
        /// Minimum cumulative amount required.
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

/// WebSocket transport for client-side payment handling.
///
/// Detects payment challenges from JSON WebSocket messages and attaches
/// credentials as JSON messages (no HTTP headers involved).
pub struct WsTransport;

/// Create a WebSocket transport instance.
pub fn ws() -> WsTransport {
    WsTransport
}

impl Transport for WsTransport {
    type Request = WsClientMessage;
    type Response = WsServerMessage;

    fn name(&self) -> &str {
        "ws"
    }

    fn is_payment_required(&self, response: &Self::Response) -> bool {
        matches!(response, WsServerMessage::Challenge { .. })
    }

    fn get_challenge(&self, response: &Self::Response) -> Result<PaymentChallenge, MppError> {
        let WsServerMessage::Challenge { challenge, .. } = response else {
            return Err(MppError::MissingHeader(
                "no challenge in WS message".to_string(),
            ));
        };

        serde_json::from_value(challenge.clone()).map_err(|e| {
            MppError::MalformedCredential(Some(format!("failed to parse WS challenge: {e}")))
        })
    }

    fn set_credential(&self, _request: Self::Request, credential: &str) -> Self::Request {
        WsClientMessage::Credential {
            credential: credential.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_transport_name() {
        let transport = ws();
        assert_eq!(transport.name(), "ws");
    }

    #[test]
    fn test_ws_client_message_credential_serde() {
        let msg = WsClientMessage::Credential {
            credential: "Payment id=\"abc\"".to_string(),
        };
        let json = msg.to_text();
        assert!(json.contains("\"type\":\"credential\""));

        let parsed: WsClientMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, WsClientMessage::Credential { .. }));
    }

    #[test]
    fn test_ws_client_message_data_serde() {
        let msg = WsClientMessage::Data {
            data: serde_json::json!({"prompt": "hello"}),
        };
        let json = msg.to_text();
        assert!(json.contains("\"type\":\"message\""));
    }

    #[test]
    fn test_ws_server_message_challenge() {
        let json = r#"{"type":"challenge","challenge":{"id":"ch-1","realm":"test","method":"tempo","intent":"charge","request":"eyJ0ZXN0IjoidmFsdWUifQ"}}"#;
        let parsed: WsServerMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(parsed, WsServerMessage::Challenge { .. }));
    }

    #[test]
    fn test_ws_server_message_need_voucher() {
        let json = r#"{"type":"needVoucher","channelId":"0xabc","requiredCumulative":"2000","acceptedCumulative":"1000","deposit":"5000"}"#;
        let parsed: WsServerMessage = serde_json::from_str(json).unwrap();
        match parsed {
            WsServerMessage::NeedVoucher { channel_id, .. } => {
                assert_eq!(channel_id, "0xabc");
            }
            _ => panic!("expected NeedVoucher"),
        }
    }

    #[test]
    fn test_is_payment_required() {
        let transport = ws();

        let challenge = WsServerMessage::Challenge {
            challenge: serde_json::json!({}),
            error: None,
        };
        assert!(transport.is_payment_required(&challenge));

        let data = WsServerMessage::Data {
            data: "hello".into(),
        };
        assert!(!transport.is_payment_required(&data));
    }

    #[test]
    fn test_set_credential() {
        let transport = ws();
        let dummy = WsClientMessage::Data {
            data: serde_json::json!({}),
        };

        let result = transport.set_credential(dummy, "Payment id=\"abc\"");
        match result {
            WsClientMessage::Credential { credential } => {
                assert_eq!(credential, "Payment id=\"abc\"");
            }
            _ => panic!("expected Credential message"),
        }
    }
}
