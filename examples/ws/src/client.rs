//! # WebSocket Payment Client
//!
//! Connects to the WS payment server, handles the challenge/credential
//! flow, and prints received fortunes.
//!
//! ## Running
//!
//! ```bash
//! # First start the server:
//! cargo run --bin ws-server
//!
//! # Then in another terminal:
//! cargo run --bin ws-client
//! ```

use futures_util::{SinkExt, StreamExt};
use mpp::client::ws::WsServerMessage;
use mpp::protocol::core::{format_authorization, PaymentPayload};
use tokio_tungstenite::tungstenite;

#[tokio::main]
async fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:3000/ws".to_string());

    println!("Connecting to {url} ...");

    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("failed to connect");

    println!("Connected!");

    while let Some(msg) = ws.next().await {
        let msg = match msg {
            Ok(tungstenite::Message::Text(text)) => text,
            Ok(tungstenite::Message::Close(_)) => {
                println!("Server closed connection");
                break;
            }
            Err(e) => {
                eprintln!("WS error: {e}");
                break;
            }
            _ => continue,
        };

        let server_msg: WsServerMessage = match serde_json::from_str(&msg) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse server message: {e}");
                continue;
            }
        };

        match server_msg {
            WsServerMessage::Challenge { challenge, .. } => {
                println!("Received payment challenge");

                // Parse the challenge
                let parsed: mpp::PaymentChallenge =
                    serde_json::from_value(challenge).expect("parse challenge");

                // Create a mock credential (in real use, sign a transaction)
                let credential = mpp::PaymentCredential::new(
                    parsed.to_echo(),
                    PaymentPayload::hash(
                        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    ),
                );
                let auth_str = format_authorization(&credential).unwrap();

                // Send credential
                let cred_msg = serde_json::json!({
                    "type": "credential",
                    "credential": auth_str,
                });
                ws.send(tungstenite::Message::Text(cred_msg.to_string().into()))
                    .await
                    .unwrap();
                println!("Sent credential");
            }
            WsServerMessage::Data { data } => {
                println!("  {data}");
            }
            WsServerMessage::NeedVoucher {
                channel_id,
                required_cumulative,
                ..
            } => {
                println!(
                    "Server needs voucher for channel {channel_id} (required: {required_cumulative})"
                );
                // In real use: sign and send a new voucher
            }
            WsServerMessage::Receipt { receipt } => {
                println!("\nPayment receipt:");
                println!("  Status: {}", receipt["status"]);
                println!("  Reference: {}", receipt["reference"]);
                break;
            }
            WsServerMessage::Error { error } => {
                eprintln!("Server error: {error}");
                // In this demo, the mock credential will fail verification.
                // A real client would use TempoProvider to sign a transaction.
                break;
            }
        }
    }
}
