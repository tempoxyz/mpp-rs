# axum Server Example

Using `mpay` with [axum](https://docs.rs/axum) for server-side payment gating.

## Dependencies

```toml
[dependencies]
mpay = "0.2"
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
```

## Basic Payment-Gated Endpoint

```rust
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use mpay::parse_authorization;
use mpay::server::{Mpay, tempo, TempoConfig, TempoChargeMethod, TempoProvider};
use std::sync::Arc;

// Create payment handler at startup
let mpay = Arc::new(Mpay::create(
    tempo(TempoConfig {
        currency: "0x20c0000000000000000000000000000000000000",
        recipient: "0xabc...123",
    })
    .rpc_url("https://rpc.moderato.tempo.xyz")
    .realm("api.example.com")
    .secret_key("my-server-secret"),
).unwrap());

async fn paid_endpoint(
    State(mpay): State<Arc<Mpay<TempoChargeMethod<TempoProvider>>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Check for payment credential
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = parse_authorization(auth_str) {
                // Verify the payment
                if let Ok(receipt) = mpay.verify_credential(&credential).await {
                    return (
                        StatusCode::OK,
                        [("payment-receipt", receipt.to_header().unwrap())],
                        "Here's your paid content!",
                    );
                }
            }
        }
    }

    // No valid payment - return 402 with challenge
    let challenge = mpay.charge("0.10").unwrap();

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, challenge.to_header().unwrap())],
        "Payment required",
    )
}
```

## With Extractor

```rust
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use mpay::{PaymentCredential, parse_authorization};

/// Extractor that requires a valid payment credential
struct RequirePayment(PaymentCredential);

#[async_trait]
impl<S> FromRequestParts<S> for RequirePayment
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::PAYMENT_REQUIRED, "missing authorization".into()))?;

        let credential = parse_authorization(auth)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

        // Verify payment here...

        Ok(RequirePayment(credential))
    }
}

// Usage
async fn handler(RequirePayment(credential): RequirePayment) -> impl IntoResponse {
    format!("Paid by: {:?}", credential.source)
}
```

## Router Setup

```rust
use axum::{routing::get, Router};

fn app() -> Router {
    Router::new()
        .route("/free", get(|| async { "Free content" }))
        .route("/paid", get(paid_endpoint))
        .route("/premium", get(premium_endpoint))
}
```

## Dynamic Pricing

```rust
async fn dynamic_pricing(
    State(mpay): State<Arc<Mpay<TempoChargeMethod<TempoProvider>>>>,
    Path(resource_id): Path<String>,
) -> impl IntoResponse {
    // Look up price for this resource
    let price = get_resource_price(&resource_id).await;

    // Generate challenge with dynamic pricing (amount in base units, e.g. "1000000" = 1 pathUSD)
    let challenge = mpay
        .charge_challenge(&price.to_string(), PATH_USD, MERCHANT_ADDRESS)
        .unwrap();

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, challenge.to_header().unwrap())],
        "Payment required",
    )
}
```
