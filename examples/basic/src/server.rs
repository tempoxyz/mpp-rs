//! # Fortune Teller API Server
//!
//! A payment-gated Fortune Teller API using the Machine Payment Protocol.
//!
//! The `/api/health` endpoint is free. The `/api/fortune` endpoint costs $1.00 and
//! returns a random fortune with a payment receipt.
//!
//! ## Running
//!
//! ```bash
//! cargo run --bin basic-server
//! ```
//!
//! The server listens on `http://localhost:3000`.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use mpp::server::{tempo, Mpp, TempoChargeMethod, TempoConfig};
use mpp::{format_www_authenticate, parse_authorization, PrivateKeySigner};
use rand::seq::IndexedRandom;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

type Payment = Mpp<TempoChargeMethod<mpp::server::TempoProvider>>;

const FORTUNES: &[&str] = &[
    "A beautiful, smart, and loving person will come into your life.",
    "A dubious friend may be an enemy in camouflage.",
    "A faithful friend is a strong defense.",
    "A fresh start will put you on your way.",
    "A golden egg of opportunity falls into your lap this month.",
    "A good time to finish up old tasks.",
    "A hunch is creativity trying to tell you something.",
    "A lifetime of happiness lies ahead of you.",
    "A light heart carries you through all the hard times.",
    "A new perspective will come with the new year.",
];

#[tokio::main]
async fn main() {
    let signer = PrivateKeySigner::random();
    let recipient = format!("{}", signer.address());
    println!("Server recipient: {recipient}");

    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());

    // Fund the server account via testnet faucet.
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(rpc_url.parse().unwrap());
    let _: Vec<B256> = provider
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");
    println!("Server account funded");

    let mut builder = tempo(TempoConfig {
        recipient: &recipient,
    })
    .rpc_url(&rpc_url)
    // Keep the demo runnable out-of-the-box while honoring required secret key semantics.
    .secret_key(
        &std::env::var("MPP_SECRET_KEY").unwrap_or_else(|_| "basic-example-secret".to_string()),
    );

    if let Ok(id) = std::env::var("CHAIN_ID") {
        builder = builder.chain_id(id.parse().expect("CHAIN_ID must be a number"));
    }

    let payment = Mpp::create(builder).expect("failed to create payment handler");

    let state = Arc::new(payment);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/fortune", get(fortune))
        .route("/api/ping", get(ping))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind");

    println!("Fortune Teller API listening on http://localhost:3000");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn ping(
    State(payment): State<Arc<Payment>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = parse_authorization(auth_str) {
                match payment.verify_credential(&credential).await {
                    Ok(receipt) => {
                        let receipt_header = receipt.to_header().unwrap_or_default();
                        return (
                            StatusCode::OK,
                            [("payment-receipt", receipt_header)],
                            Json(serde_json::json!({ "pong": true })),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        let body = serde_json::json!({ "error": e.to_string() });
                        return (StatusCode::PAYMENT_REQUIRED, Json(body)).into_response();
                    }
                }
            }
        }
    }

    match payment.charge("0.01") {
        Ok(challenge) => match format_www_authenticate(&challenge) {
            Ok(www_auth) => (
                StatusCode::PAYMENT_REQUIRED,
                [(header::WWW_AUTHENTICATE, www_auth)],
                Json(serde_json::json!({ "error": "Payment Required" })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn fortune(
    State(payment): State<Arc<Payment>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Check for payment credential in Authorization header
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = parse_authorization(auth_str) {
                match payment.verify_credential(&credential).await {
                    Ok(receipt) => {
                        let fortune = FORTUNES
                            .choose(&mut rand::rng())
                            .unwrap_or(&"No fortune today.");
                        let receipt_header = receipt.to_header().unwrap_or_default();
                        return (
                            StatusCode::OK,
                            [("payment-receipt", receipt_header)],
                            Json(serde_json::json!({ "fortune": fortune })),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        let body = serde_json::json!({ "error": e.to_string() });
                        return (StatusCode::PAYMENT_REQUIRED, Json(body)).into_response();
                    }
                }
            }
        }
    }

    // No valid credential — return 402 with challenge
    match payment.charge("1") {
        Ok(challenge) => match format_www_authenticate(&challenge) {
            Ok(www_auth) => (
                StatusCode::PAYMENT_REQUIRED,
                [(header::WWW_AUTHENTICATE, www_auth)],
                Json(serde_json::json!({ "error": "Payment Required" })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
