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

    let app = Router::new().route("/ws", get(ws_handler)).with_state(mpp);

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
        use axum::extract::ws::Message;

        // 1. Send challenge (use charge_challenge with explicit params for mock setup)
        let challenge = match mpp.charge_challenge("10000", "0x0", "0x0") {
            Ok(c) => c,
            Err(e) => {
                let _ = socket
                    .send(Message::Text(
                        WsResponse::Error {
                            error: e.to_string(),
                        }
                        .to_text()
                        .into(),
                    ))
                    .await;
                return;
            }
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
            let msg = match socket.recv().await {
                Some(Ok(Message::Text(text))) => text,
                Some(Ok(Message::Close(_))) | None => return,
                _ => continue,
            };

            let ws_msg: WsMessage = match serde_json::from_str(&msg) {
                Ok(m) => m,
                Err(_) => {
                    let _ = socket
                        .send(Message::Text(
                            WsResponse::Error {
                                error: "Invalid message format".into(),
                            }
                            .to_text()
                            .into(),
                        ))
                        .await;
                    continue;
                }
            };

            match ws_msg {
                WsMessage::Credential { credential } => {
                    let parsed = match mpp::parse_authorization(&credential) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = socket
                                .send(Message::Text(
                                    WsResponse::Error {
                                        error: e.to_string(),
                                    }
                                    .to_text()
                                    .into(),
                                ))
                                .await;
                            continue;
                        }
                    };

                    match mpp.verify_credential(&parsed).await {
                        Ok(receipt) => {
                            println!("Payment verified: {}", receipt.reference);
                            break receipt;
                        }
                        Err(e) => {
                            let _ = socket
                                .send(Message::Text(
                                    WsResponse::Error {
                                        error: e.message.clone(),
                                    }
                                    .to_text()
                                    .into(),
                                ))
                                .await;
                        }
                    }
                }
                _ => {
                    let _ = socket
                        .send(Message::Text(
                            WsResponse::Error {
                                error: "Send credential first".into(),
                            }
                            .to_text()
                            .into(),
                        ))
                        .await;
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
