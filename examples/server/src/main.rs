//! axum server example demonstrating payment-gated endpoints with mpay.
//!
//! Run with: `MERCHANT_ADDRESS=0x... cargo run`
//!
//! Then test:
//! - GET http://localhost:3000/free → 200 OK (no payment)
//! - GET http://localhost:3000/paid → 402 Payment Required (needs credential)

use axum::{
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use mpay::protocol::methods::tempo;
use mpay::{Credential, Receipt};
use std::sync::LazyLock;

const REALM: &str = "api.example.com";
const ALPHA_USD: &str = "0x20c0000000000000000000000000000000000001";

static MERCHANT_ADDRESS: LazyLock<String> = LazyLock::new(|| {
    std::env::var("MERCHANT_ADDRESS").expect("MERCHANT_ADDRESS must be set")
});

#[tokio::main]
async fn main() {
    LazyLock::force(&MERCHANT_ADDRESS);

    let app = Router::new()
        .route("/free", get(free_endpoint))
        .route("/paid", get(paid_endpoint));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn free_endpoint() -> &'static str {
    "Free content - no payment required"
}

async fn paid_endpoint(headers: HeaderMap) -> impl IntoResponse {
    if let Some(credential) = parse_credential(&headers) {
        // TODO: Verify the credential and submit the transaction
        // For real verification, use mpay::server::TempoChargeMethod which
        // broadcasts the tx and returns a receipt with the real tx hash.
        let tx_ref = credential
            .payload
            .tx_hash()
            .unwrap_or("pending")
            .to_string();
        let receipt = Receipt::Receipt::success("tempo", tx_ref);
        return (
            StatusCode::OK,
            [("payment-receipt", receipt.to_header().unwrap())],
            "Here's your paid content!",
        )
            .into_response();
    }

    let challenge =
        tempo::charge_challenge(REALM, "1000000", ALPHA_USD, &MERCHANT_ADDRESS).unwrap();

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, challenge.to_header().unwrap())],
        "Payment required",
    )
        .into_response()
}

fn parse_credential(headers: &HeaderMap) -> Option<Credential::PaymentCredential> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Credential::parse_authorization(s).ok())
}
