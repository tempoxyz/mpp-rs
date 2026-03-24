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

use axum::{extract::ws::WebSocketUpgrade, routing::get, Router};
use mpp::server::ws::{WsMessage, WsResponse};
use mpp::server::{tempo, Mpp, TempoConfig};
use std::sync::Arc;

const FORTUNES: &[&str] = &[
    "A beautiful day awaits you.",
    "Good things come to those who pay.",
    "Your code will compile on the first try.",
    "A WebSocket connection is worth a thousand HTTP requests.",
    "Fortune favors the persistent.",
];

type Payment = Mpp<mpp::server::TempoChargeMethod<mpp::server::TempoProvider>>;

#[tokio::main]
async fn main() {
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .rpc_url("https://rpc.moderato.tempo.xyz")
        .secret_key("ws-example-secret"),
    )
    .expect("failed to create Mpp");

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
        use axum::extract::ws::Message;

        // 1. Send challenge
        let challenge = match mpp.charge("0.01") {
            Ok(c) => c,
            Err(e) => {
                let _ = socket
                    .send(Message::Text(
                        WsResponse::Error { error: e.to_string() }.to_text().into(),
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
                                    WsResponse::Error { error: e.to_string() }.to_text().into(),
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
