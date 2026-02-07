//! axum server example demonstrating payment-gated endpoints with mpay.
//!
//! # Running the server
//!
//! ```bash
//! MERCHANT_ADDRESS=0x... cargo run
//! ```
//!
//! # Testing with curl
//!
//! ```bash
//! # Free endpoint - no payment required
//! curl http://localhost:3000/free
//! # → "Free content - no payment required"
//!
//! # Paid endpoint without credentials - returns 402
//! curl -i http://localhost:3000/paid
//! # → HTTP/1.1 402 Payment Required
//! # → WWW-Authenticate: Payment realm="api.example.com", ...
//! ```
//!
//! # Testing with purl (automatic payment)
//!
//! [purl](https://github.com/tempoxyz/purl) handles 402 responses automatically,
//! prompting for payment and retrying with credentials.
//!
//! ```bash
//! # Free endpoint works normally
//! purl http://localhost:3000/free
//! # → "Free content - no payment required"
//!
//! # Paid endpoint - purl detects 402, pays, and retries automatically
//! purl http://localhost:3000/paid
//! # → Received 402 Payment Required
//! # → Payment challenge: 1.00 pathUSD to 0x...
//! # → Confirm payment? [y/N]: y
//! # → Payment sent: 0x...
//! # → "Here's your paid content!"
//!
//! # Skip confirmation prompt with -y
//! purl -y http://localhost:3000/paid
//!
//! # Verbose mode to see headers
//! purl -vv http://localhost:3000/paid
//! ```

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use mpay::server::{Mpay, tempo, TempoChargeMethod, TempoConfig};
use mpay::{parse_authorization, PaymentCredential};
use std::sync::Arc;

const REALM: &str = "api.example.com";
const RPC_URL: &str = "https://rpc.moderato.tempo.xyz";
const SECRET_KEY: &str = "example-server-secret-key";

type PaymentHandler = Mpay<TempoChargeMethod<mpay::server::TempoProvider>>;

#[tokio::main]
async fn main() {
    let merchant_address =
        std::env::var("MERCHANT_ADDRESS").expect("MERCHANT_ADDRESS must be set");

    let payment = Mpay::create(
        tempo(TempoConfig {
            currency: "0x20c0000000000000000000000000000000000001",
            recipient: &merchant_address,
        })
        .rpc_url(RPC_URL)
        .realm(REALM)
        .secret_key(SECRET_KEY),
    )
    .expect("failed to create payment handler");

    let app = Router::new()
        .route("/free", get(free_endpoint))
        .route("/paid", get(paid_endpoint))
        .with_state(Arc::new(payment));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn free_endpoint() -> &'static str {
    "Free content - no payment required"
}

async fn paid_endpoint(
    State(payment): State<Arc<PaymentHandler>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(credential) = parse_credential(&headers) {
        match payment.verify_credential(&credential).await {
            Ok(receipt) => {
                return (
                    StatusCode::OK,
                    [("payment-receipt", receipt.to_header().unwrap())],
                    "Here's your paid content!",
                )
                    .into_response();
            }
            Err(e) => {
                eprintln!("Payment verification failed: {}", e);
            }
        }
    }

    let challenge = payment.charge("1.00").unwrap();

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, challenge.to_header().unwrap())],
        "Payment required",
    )
        .into_response()
}

fn parse_credential(headers: &HeaderMap) -> Option<PaymentCredential> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| parse_authorization(s).ok())
}
