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
//! # → Payment challenge: 1.00 αUSD to 0x...
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
use mpay::{ChargeRequest, PaymentCredential, parse_authorization};
use mpay::protocol::methods::tempo;
use mpay::server::{tempo_provider, ChargeMethod, TempoChargeMethod};
use std::sync::{Arc, LazyLock};

const REALM: &str = "api.example.com";
const ALPHA_USD: &str = "0x20c0000000000000000000000000000000000001";
const RPC_URL: &str = "https://rpc.moderato.tempo.xyz";

static MERCHANT_ADDRESS: LazyLock<String> = LazyLock::new(|| {
    std::env::var("MERCHANT_ADDRESS").expect("MERCHANT_ADDRESS must be set")
});

#[tokio::main]
async fn main() {
    LazyLock::force(&MERCHANT_ADDRESS);

    let provider = tempo_provider(RPC_URL);
    let charge_method = TempoChargeMethod::new(provider);

    let app = Router::new()
        .route("/free", get(free_endpoint))
        .route("/paid", get(paid_endpoint))
        .with_state(Arc::new(charge_method));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn free_endpoint() -> &'static str {
    "Free content - no payment required"
}

async fn paid_endpoint<M: ChargeMethod>(
    State(method): State<Arc<M>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request = ChargeRequest {
        amount: "1000000".into(),
        currency: ALPHA_USD.into(),
        recipient: Some(MERCHANT_ADDRESS.clone()),
        ..Default::default()
    };

    if let Some(credential) = parse_credential(&headers) {
        match method.verify(&credential, &request).await {
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

    let challenge =
        tempo::charge_challenge(REALM, "1000000", ALPHA_USD, &MERCHANT_ADDRESS).unwrap();

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
