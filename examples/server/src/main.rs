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
use mpay::{Challenge, Credential, Receipt};
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
    // Check for payment credential
    if let Some(credential) = parse_credential(&headers) {
        if verify_payment(&credential).await.is_ok() {
            let receipt = Receipt::Receipt::success("tempo", "0x...");
            let header = Receipt::format_receipt(&receipt).unwrap();
            return (
                StatusCode::OK,
                [("payment-receipt", header)],
                "Here's your paid content!",
            )
                .into_response();
        }
    }

    // Return 402 with payment challenge
    let challenge =
        tempo::charge_challenge(REALM, "1000000", ALPHA_USD, &MERCHANT_ADDRESS).unwrap();
    let www_auth = Challenge::format_www_authenticate(&challenge).unwrap();

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, www_auth)],
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

async fn verify_payment(_credential: &Credential::PaymentCredential) -> Result<(), ()> {
    // TODO: Verify the payment credential (check signature, submit tx, etc.)
    Ok(())
}
