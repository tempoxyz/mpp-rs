//! # WebSocket Payment Server
//!
//! A payment-gated WebSocket server that streams fortunes after payment.
//!
//! ## Running
//!
//! ```bash
//! cargo run --bin ws-server
//! ```
//!
//! The server listens on `ws://localhost:3000/ws`.

use std::future::Future;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::{extract::ws::WebSocketUpgrade, routing::get, Router};
use mpp::protocol::core::Receipt;
use mpp::protocol::intents::ChargeRequest;
use mpp::protocol::traits::{ChargeMethod, VerificationError};
use mpp::server::ws::{WsMessage, WsResponse};
use mpp::server::Mpp;
use mpp::PaymentCredential;

const FORTUNES: &[&str] = &[
    "A beautiful day awaits you.",
    "Good things come to those who pay.",
    "Your code will compile on the first try.",
    "A WebSocket connection is worth a thousand HTTP requests.",
    "Fortune favors the persistent.",
];

/// Mock charge method that accepts any credential — for demo purposes only.
#[derive(Clone)]
struct MockMethod;

#[allow(clippy::manual_async_fn)]
impl ChargeMethod for MockMethod {
    fn method(&self) -> &str {
        "mock"
    }

    fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        async { Ok(Receipt::success("mock", "mock-ws-receipt")) }
    }
}

type Payment = Mpp<MockMethod>;

#[tokio::main]
async fn main() {
    let mpp = Mpp::new(MockMethod, "ws-example.local", "ws-example-secret");

    let mpp = Arc::new(mpp);

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(mpp);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("failed to bind");
    println!("WebSocket server listening on ws://127.0.0.1:3000/ws");

    axum::serve(listener, app).await.expect("server error");
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    axum::extract::State(mpp): axum::extract::State<Arc<Payment>>,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        // 1. Send challenge
        let Ok(challenge) = mpp.charge_challenge("10000", "0x0", "0x0") else {
            let _ = send_error(&mut socket, "Failed to create challenge").await;
            return;
        };

        println!("Sending challenge...");
        let challenge_resp = WsResponse::Challenge {
            challenge: serde_json::to_value(&challenge).unwrap(),
            error: None,
        };
        if socket
            .send(Message::Text(challenge_resp.to_text().into()))
            .await
            .is_err()
        {
            return;
        }

        // 2. Wait for credential
        let receipt = loop {
            let Some(Ok(Message::Text(msg))) = socket.recv().await else {
                return;
            };

            let Ok(WsMessage::Credential { credential }) = serde_json::from_str(&msg) else {
                let _ = send_error(&mut socket, "Expected credential message").await;
                continue;
            };

            let Ok(parsed) = mpp::parse_authorization(&credential) else {
                let _ = send_error(&mut socket, "Malformed credential").await;
                continue;
            };

            match mpp.verify_credential(&parsed).await {
                Ok(receipt) => {
                    println!("Payment verified: {}", receipt.reference);
                    break receipt;
                }
                Err(e) => {
                    let _ = send_error(&mut socket, &e.message).await;
                }
            }
        };

        // 3. Stream fortunes
        for i in 1..=3 {
            let fortune = FORTUNES[i % FORTUNES.len()];
            let msg = WsResponse::Data {
                data: format!("Fortune #{i}: {fortune}"),
            };
            if socket
                .send(Message::Text(msg.to_text().into()))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // 4. Send receipt
        let receipt_msg = WsResponse::Receipt {
            receipt: serde_json::to_value(&receipt).unwrap(),
        };
        let _ = socket
            .send(Message::Text(receipt_msg.to_text().into()))
            .await;
        println!("Session complete");
    })
}

async fn send_error(socket: &mut WebSocket, error: &str) {
    let msg = WsResponse::Error {
        error: error.to_string(),
    };
    let _ = socket.send(Message::Text(msg.to_text().into())).await;
}
