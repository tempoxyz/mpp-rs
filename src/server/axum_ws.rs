//! Axum WebSocket handler for payment-gated session streams.
//!
//! Provides [`MppWsHandler`] which handles the full WebSocket payment flow:
//!
//! 1. Client connects via WebSocket upgrade
//! 2. First message must be a credential — if missing, server sends challenge
//! 3. On valid credential, the user-provided callback generates the stream
//! 4. Application data is sent as `{ "type": "message", "data": "..." }` frames
//! 5. Final receipt is sent as `{ "type": "receipt", ... }` before close
//!
//! For session (metered) flows, the callback can integrate with
//! [`sse::serve`](super::sse::serve) or implement custom metering.
//!
//! # Example
//!
//! ```ignore
//! use axum::{routing::get, Router};
//! use mpp::server::axum_ws::ws_handler;
//! use mpp::server::ws::WsResponse;
//! use std::sync::Arc;
//!
//! async fn handle(ws: axum::extract::ws::WebSocketUpgrade, state: ...) -> impl IntoResponse {
//!     ws_handler(ws, challenger, |receipt| async move {
//!         vec!["hello".to_string(), "world".to_string()]
//!     }).await
//! }
//! ```

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};

use super::axum::ChargeChallenger;
use super::ws::WsResponse;
use crate::protocol::core::Receipt;

/// Handle a WebSocket upgrade with payment gating.
///
/// This function:
/// 1. Upgrades the HTTP connection to WebSocket
/// 2. Waits for a credential message from the client
/// 3. If no credential or invalid, sends a challenge and waits again
/// 4. On valid credential, calls `on_verified` with the receipt
/// 5. Sends each yielded item as a `message` frame, then sends the receipt
///
/// # Arguments
///
/// * `ws` - The axum WebSocket upgrade extractor
/// * `challenger` - Payment challenge generator and verifier
/// * `amount` - Dollar amount to charge (e.g., "0.10")
/// * `on_verified` - Async callback that produces items to stream after payment
pub fn ws_handler<F, Fut, I>(
    ws: WebSocketUpgrade,
    challenger: Arc<dyn ChargeChallenger>,
    amount: &'static str,
    on_verified: F,
) -> impl IntoResponse
where
    F: FnOnce(Receipt) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = I> + Send + 'static,
    I: IntoIterator<Item = String> + 'static,
    <I as IntoIterator>::IntoIter: Send,
{
    ws.on_upgrade(move |socket| handle_ws_session(socket, challenger, amount, on_verified))
}

async fn handle_ws_session<F, Fut, I>(
    socket: WebSocket,
    challenger: Arc<dyn ChargeChallenger>,
    amount: &str,
    on_verified: F,
) where
    F: FnOnce(Receipt) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = I> + Send + 'static,
    I: IntoIterator<Item = String>,
{
    let (mut sender, mut receiver) = socket.split();

    // Send initial challenge
    let challenge = match challenger.challenge(amount, super::axum::ChallengeOptions::default()) {
        Ok(c) => c,
        Err(e) => {
            let _ = send_error(&mut sender, format!("Failed to create challenge: {e}")).await;
            return;
        }
    };

    let challenge_msg = WsResponse::Challenge {
        challenge: serde_json::to_value(&challenge)
            .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"})),
        error: None,
    };
    if sender
        .send(Message::Text(challenge_msg.to_text().into()))
        .await
        .is_err()
    {
        return;
    }

    // Wait for credential
    let receipt = loop {
        let msg = match receiver.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_))) | None => return,
            _ => continue,
        };

        // Try to parse as a credential message
        let ws_msg: super::ws::WsMessage = match serde_json::from_str(&msg) {
            Ok(m) => m,
            Err(_) => {
                send_error(&mut sender, "Invalid message format").await;
                continue;
            }
        };

        match ws_msg {
            super::ws::WsMessage::Credential { credential } => {
                let parsed = match crate::protocol::core::parse_authorization(&credential) {
                    Ok(c) => c,
                    Err(_) => {
                        send_error(&mut sender, "Malformed credential").await;
                        continue;
                    }
                };

                if parsed.challenge.id != challenge.id {
                    send_error(&mut sender, "Credential challenge ID mismatch").await;
                    continue;
                }

                match challenger.verify_payment(&credential).await {
                    Ok(receipt) => break receipt,
                    Err(e) => {
                        let challenge_resp = WsResponse::Challenge {
                            challenge: serde_json::to_value(&challenge).unwrap_or_default(),
                            error: Some(e),
                        };
                        let _ = sender
                            .send(Message::Text(challenge_resp.to_text().into()))
                            .await;
                        continue;
                    }
                }
            }
            _ => {
                send_error(&mut sender, "Expected credential message").await;
                continue;
            }
        }
    };

    // Payment verified — stream content
    let items = on_verified(receipt.clone()).await;
    for item in items {
        let msg = WsResponse::Data { data: item };
        if sender
            .send(Message::Text(msg.to_text().into()))
            .await
            .is_err()
        {
            return;
        }
    }

    // Send receipt
    let receipt_msg = WsResponse::Receipt {
        receipt: serde_json::to_value(&receipt)
            .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"})),
    };
    let _ = sender
        .send(Message::Text(receipt_msg.to_text().into()))
        .await;
}

/// Send a JSON error frame to the client.
async fn send_error(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    error: impl Into<String>,
) {
    let msg = WsResponse::Error {
        error: error.into(),
    };
    let _ = sender.send(Message::Text(msg.to_text().into())).await;
}
