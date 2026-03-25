//! # Stripe Fortune Teller API Server
//!
//! A payment-gated Fortune Teller API using Stripe's Shared Payment Token (SPT)
//! flow via the Machine Payment Protocol.
//!
//! Two endpoints:
//!
//! - `POST /api/create-spt` — proxy for SPT creation (secret key stays server-side)
//! - `GET  /api/fortune`    — paid endpoint ($1.00 per fortune)
//!
//! ## Running
//!
//! ```bash
//! export STRIPE_SECRET_KEY=sk_test_...
//! cargo run --bin stripe-server
//! ```
//!
//! The server listens on `http://localhost:3000`.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use mpp::server::{stripe, Mpp, StripeChargeMethod, StripeConfig};
use mpp::{format_www_authenticate, parse_authorization};
use rand::seq::IndexedRandom;
use std::sync::Arc;

type Payment = Mpp<StripeChargeMethod>;

const FORTUNES: &[&str] = &[
    "A beautiful, smart, and loving person will come into your life.",
    "A dubious friend may be an enemy in camouflage.",
    "A faithful friend is a strong defense.",
    "A fresh start will put you on your way.",
    "A golden egg of opportunity falls into your lap this month.",
    "A good time to finish up old tasks.",
    "A light heart carries you through all the hard times ahead.",
    "A smooth long journey! Great expectations.",
];

struct AppState {
    payment: Payment,
    stripe_secret_key: String,
}

#[tokio::main]
async fn main() {
    let secret_key =
        std::env::var("STRIPE_SECRET_KEY").expect("STRIPE_SECRET_KEY env var required");
    let network_id =
        std::env::var("STRIPE_NETWORK_ID").unwrap_or_else(|_| "internal".to_string());

    let payment = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: &secret_key,
            network_id: &network_id,
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .secret_key(
            &std::env::var("MPP_SECRET_KEY")
                .unwrap_or_else(|_| "stripe-example-secret".to_string()),
        ),
    )
    .expect("failed to create Stripe payment handler");

    let state = Arc::new(AppState {
        payment,
        stripe_secret_key: secret_key,
    });

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/create-spt", post(create_spt))
        .route("/api/fortune", get(fortune))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind");

    println!("Stripe Fortune Teller API listening on http://localhost:3000");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Proxy endpoint for SPT creation.
///
/// The client calls this with a payment method ID and challenge details.
/// We call Stripe's test SPT endpoint using our secret key.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSptRequest {
    payment_method: String,
    amount: String,
    currency: String,
    expires_at: u64,
}

async fn create_spt(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateSptRequest>,
) -> impl IntoResponse {
    let auth_value =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{}:", state.stripe_secret_key));

    let params = [
        ("payment_method", body.payment_method),
        ("usage_limits[currency]", body.currency),
        ("usage_limits[max_amount]", body.amount),
        ("usage_limits[expires_at]", body.expires_at.to_string()),
    ];

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.stripe.com/v1/test_helpers/shared_payment/granted_tokens")
        .header("Authorization", format!("Basic {auth_value}"))
        .form(&params)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let json: serde_json::Value = r.json().await.unwrap_or_default();
            let spt = json["id"].as_str().unwrap_or_default();
            (StatusCode::OK, Json(serde_json::json!({ "spt": spt }))).into_response()
        }
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            eprintln!("Stripe SPT error ({status}): {body}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "SPT creation failed" })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn fortune(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Check for payment credential in Authorization header
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = parse_authorization(auth_str) {
                match state.payment.verify_credential(&credential).await {
                    Ok(receipt) => {
                        let fortune = FORTUNES
                            .choose(&mut rand::rng())
                            .unwrap_or(&"No fortune today.");
                        let receipt_header = receipt.to_header().unwrap_or_default();
                        return (
                            StatusCode::OK,
                            [("payment-receipt", receipt_header)],
                            Json(serde_json::json!({
                                "fortune": fortune,
                                "receipt": receipt.reference,
                            })),
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
    match state.payment.stripe_charge("1") {
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
