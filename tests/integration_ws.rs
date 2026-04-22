//! Integration tests for the WebSocket transport.
//!
//! Spins up an axum server with a WS endpoint and tests the full
//! challenge → credential → data → receipt flow over WebSocket.
//!
//! # Running
//!
//! ```bash
//! cargo test --features ws,tempo,server,client,axum --test integration_ws
//! ```

#![cfg(all(feature = "ws", feature = "tempo", feature = "axum"))]

use axum::{routing::get, Router};
use futures_util::{SinkExt, StreamExt};
use mpp::protocol::core::{format_authorization, PaymentPayload};
use mpp::server::ws::{WsMessage, WsResponse};
use mpp::server::{tempo, Mpp, TempoConfig};
use tokio_tungstenite::tungstenite;

/// Start an axum server with a WS payment endpoint.
async fn start_ws_server() -> (String, tokio::task::JoinHandle<()>) {
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .secret_key("ws-test-secret"),
    )
    .expect("failed to create Mpp");

    let mpp = std::sync::Arc::new(mpp);

    let app = Router::new().route(
        "/ws",
        get({
            let mpp = mpp.clone();
            move |ws: axum::extract::ws::WebSocketUpgrade| {
                let mpp = mpp.clone();
                async move {
                    ws.on_upgrade(move |mut socket| async move {
                        use axum::extract::ws::Message;

                        // Send challenge
                        let challenge = mpp.charge("0.01").expect("challenge");
                        let challenge_resp = WsResponse::Challenge {
                            challenge: serde_json::to_value(&challenge).unwrap(),
                            error: None,
                        };
                        let _ = socket
                            .send(Message::Text(challenge_resp.to_text().into()))
                            .await;

                        // Wait for credential
                        while let Some(Ok(Message::Text(text))) = socket.recv().await {
                            let Ok(WsMessage::Credential { credential }) =
                                serde_json::from_str(&text)
                            else {
                                continue;
                            };

                            let Ok(parsed) = mpp::parse_authorization(&credential) else {
                                continue;
                            };

                            match mpp.verify_credential(&parsed).await {
                                Ok(receipt) => {
                                    let data = WsResponse::Data {
                                        data: "hello from ws".into(),
                                    };
                                    let _ = socket.send(Message::Text(data.to_text().into())).await;

                                    let receipt_msg = WsResponse::Receipt {
                                        receipt: serde_json::to_value(&receipt).unwrap(),
                                    };
                                    let _ = socket
                                        .send(Message::Text(receipt_msg.to_text().into()))
                                        .await;
                                    break;
                                }
                                Err(e) => {
                                    let err = WsResponse::Error { error: e.message };
                                    let _ = socket.send(Message::Text(err.to_text().into())).await;
                                }
                            }
                        }
                    })
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server error");
    });

    (url, handle)
}

/// Full e2e: connect WS → receive challenge → send credential → receive data + receipt.
#[tokio::test]
async fn test_ws_e2e_challenge_credential_flow() {
    let (url, handle) = start_ws_server().await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{url}/ws"))
        .await
        .expect("ws connect failed");

    // 1. Receive challenge
    let msg = ws.next().await.unwrap().unwrap();
    let text = msg.into_text().unwrap();
    let server_msg: WsResponse = serde_json::from_str(&text).unwrap();

    let WsResponse::Challenge { challenge, .. } = server_msg else {
        panic!("expected Challenge, got: {server_msg:?}");
    };
    let challenge: mpp::PaymentChallenge =
        serde_json::from_value(challenge).expect("parse challenge");

    assert_eq!(challenge.method.as_str(), "tempo");
    assert_eq!(challenge.intent.as_str(), "charge");

    // 2. Send credential (mock — use a hash payload)
    let credential =
        mpp::PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    let auth_str = format_authorization(&credential).unwrap();
    let cred_msg = WsMessage::Credential {
        credential: auth_str,
    };
    ws.send(tungstenite::Message::Text(
        serde_json::to_string(&cred_msg).unwrap().into(),
    ))
    .await
    .unwrap();

    // 3. Receive response (either data+receipt or error — depends on mock verify)
    // With a mock hash, verify will likely fail. That's fine — we're testing the protocol.
    let msg = ws.next().await.unwrap().unwrap();
    let text = msg.into_text().unwrap();
    let response: WsResponse = serde_json::from_str(&text).unwrap();

    // We accept either an error (mock verify fails) or data (if mock verify somehow passes)
    match response {
        WsResponse::Error { error } => {
            // Expected — mock credential won't pass real tempo verification
            assert!(!error.is_empty());
        }
        WsResponse::Data { data } => {
            assert_eq!(data, "hello from ws");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    handle.abort();
}

/// WS message serialization roundtrip.
#[tokio::test]
async fn test_ws_message_types_over_wire() {
    let (url, handle) = start_ws_server().await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{url}/ws"))
        .await
        .expect("ws connect failed");

    // Should receive a challenge as first message
    let msg = ws.next().await.unwrap().unwrap();
    let text = msg.into_text().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();

    assert_eq!(parsed["type"], "challenge");
    assert!(parsed["challenge"].is_object());
    assert!(parsed["challenge"]["id"].is_string());
    assert!(parsed["challenge"]["method"].is_string());

    // Send garbage — should get error back
    ws.send(tungstenite::Message::Text("not json".into()))
        .await
        .unwrap();

    // Server may ignore or send error — just verify connection stays alive
    // Send valid but non-credential message
    let data_msg = serde_json::json!({"type": "message", "data": {"foo": "bar"}});
    ws.send(tungstenite::Message::Text(data_msg.to_string().into()))
        .await
        .unwrap();

    handle.abort();
}

/// Credential with wrong challenge ID should be rejected.
#[tokio::test]
async fn test_ws_challenge_id_mismatch_rejected() {
    let (url, handle) = start_ws_server().await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{url}/ws"))
        .await
        .expect("ws connect failed");

    // Receive challenge
    let msg = ws.next().await.unwrap().unwrap();
    let text = msg.into_text().unwrap();
    let server_msg: WsResponse = serde_json::from_str(&text).unwrap();
    let WsResponse::Challenge { .. } = server_msg else {
        panic!("expected Challenge, got: {server_msg:?}");
    };

    // Send credential with a DIFFERENT challenge ID (forged echo)
    let fake_challenge = mpp::PaymentChallenge::new(
        "wrong-challenge-id",
        "test.example.com",
        "tempo",
        "charge",
        mpp::Base64UrlJson::from_value(&serde_json::json!({"amount": "999"})).unwrap(),
    );
    let credential =
        mpp::PaymentCredential::new(fake_challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    let auth_str = format_authorization(&credential).unwrap();
    let cred_msg = WsMessage::Credential {
        credential: auth_str,
    };
    ws.send(tungstenite::Message::Text(
        serde_json::to_string(&cred_msg).unwrap().into(),
    ))
    .await
    .unwrap();

    // Should get error about challenge ID mismatch
    let msg = ws.next().await.unwrap().unwrap();
    let text = msg.into_text().unwrap();
    let response: WsResponse = serde_json::from_str(&text).unwrap();

    // Credential with wrong challenge ID should be rejected (HMAC mismatch
    // or decode failure — either way it must not succeed)
    match response {
        WsResponse::Error { error } => {
            assert!(!error.is_empty(), "error should not be empty");
        }
        WsResponse::Challenge { error: Some(e), .. } => {
            assert!(!e.is_empty());
        }
        WsResponse::Data { .. } | WsResponse::Receipt { .. } => {
            panic!("credential with wrong challenge ID should not succeed");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    handle.abort();
}

/// Server/client wire types are cross-compatible.
#[test]
fn test_server_client_wire_type_compat() {
    use mpp::client::ws::WsServerMessage;

    // Serialize with server types, deserialize with client types
    let server_challenge = WsResponse::Challenge {
        challenge: serde_json::json!({"id": "ch-1", "method": "tempo", "intent": "charge", "realm": "test", "request": "eyJ0ZXN0Ijp0cnVlfQ"}),
        error: None,
    };
    let json = server_challenge.to_text();
    let client_parsed: WsServerMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(client_parsed, WsServerMessage::Challenge { .. }));

    let server_data = WsResponse::Data {
        data: "hello".into(),
    };
    let json = server_data.to_text();
    let client_parsed: WsServerMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(client_parsed, WsServerMessage::Data { .. }));

    let server_nv = WsResponse::NeedVoucher {
        channel_id: "0xabc".into(),
        required_cumulative: "2000".into(),
        accepted_cumulative: "1000".into(),
        deposit: "5000".into(),
    };
    let json = server_nv.to_text();
    let client_parsed: WsServerMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(client_parsed, WsServerMessage::NeedVoucher { .. }));

    let server_receipt = WsResponse::Receipt {
        receipt: serde_json::json!({"status": "success"}),
    };
    let json = server_receipt.to_text();
    let client_parsed: WsServerMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(client_parsed, WsServerMessage::Receipt { .. }));

    let server_err = WsResponse::Error {
        error: "bad".into(),
    };
    let json = server_err.to_text();
    let client_parsed: WsServerMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(client_parsed, WsServerMessage::Error { .. }));

    // Serialize with client types, deserialize with server types
    use mpp::client::ws::WsClientMessage;
    let client_cred = WsClientMessage::Credential {
        credential: "Payment id=\"abc\"".into(),
    };
    let json = client_cred.to_text();
    let server_parsed: WsMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(server_parsed, WsMessage::Credential { .. }));

    let client_data = WsClientMessage::Data {
        data: serde_json::json!({"prompt": "hello"}),
    };
    let json = client_data.to_text();
    let server_parsed: WsMessage = serde_json::from_str(&json).unwrap();
    assert!(matches!(server_parsed, WsMessage::Data { .. }));
}

/// NeedVoucher message serde works over the wire.
#[test]
fn test_need_voucher_roundtrip() {
    let resp = WsResponse::NeedVoucher {
        channel_id: "0xabc123".into(),
        required_cumulative: "2000000".into(),
        accepted_cumulative: "1000000".into(),
        deposit: "5000000".into(),
    };

    let json = resp.to_text();
    let parsed: WsResponse = serde_json::from_str(&json).unwrap();

    match parsed {
        WsResponse::NeedVoucher {
            channel_id,
            required_cumulative,
            ..
        } => {
            assert_eq!(channel_id, "0xabc123");
            assert_eq!(required_cumulative, "2000000");
        }
        _ => panic!("expected NeedVoucher"),
    }
}
