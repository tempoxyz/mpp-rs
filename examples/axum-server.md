# axum Server Example

Using `mpay` with [axum](https://docs.rs/axum) for server-side payment gating.

## Dependencies

```toml
[dependencies]
mpay = "0.1"
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
```

## Basic Payment-Gated Endpoint

```rust
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use mpay::{Challenge, Credential, Receipt};

async fn paid_endpoint(headers: HeaderMap) -> impl IntoResponse {
    // Check for payment credential
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = Credential::from_authorization(auth_str) {
                // Verify the payment on-chain
                if verify_payment(&credential).await.is_ok() {
                    let receipt = Receipt {
                        status: "success".into(),
                        timestamp: Some(chrono::Utc::now().to_rfc3339()),
                        reference: credential.payload.get("hash").map(|h| h.to_string()),
                    };

                    return (
                        StatusCode::OK,
                        [(
                            header::HeaderName::from_static("payment-receipt"),
                            receipt.to_payment_receipt(),
                        )],
                        "Here's your paid content!",
                    );
                }
            }
        }
    }

    // No valid payment - return 402 with challenge
    let challenge = Challenge {
        id: uuid::Uuid::new_v4().to_string(),
        method: "tempo".into(),
        intent: "charge".into(),
        request: serde_json::json!({
            "amount": "1000000",
            "asset": "0x...",
            "destination": "0x..."
        }),
    };

    (
        StatusCode::PAYMENT_REQUIRED,
        [(
            header::WWW_AUTHENTICATE,
            challenge.to_www_authenticate("api.example.com"),
        )],
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
use mpay::Credential;

/// Extractor that requires a valid payment credential
struct RequirePayment(Credential);

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

        let credential = Credential::from_authorization(auth)
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
async fn dynamic_pricing(headers: HeaderMap, Path(resource_id): Path<String>) -> impl IntoResponse {
    // Look up price for this resource
    let price = get_resource_price(&resource_id).await;

    let challenge = Challenge {
        id: uuid::Uuid::new_v4().to_string(),
        method: "tempo".into(),
        intent: "charge".into(),
        request: serde_json::json!({
            "amount": price.to_string(),
            "asset": USDC_ADDRESS,
            "destination": MERCHANT_ADDRESS,
            "memo": resource_id,
        }),
    };

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, challenge.to_www_authenticate("api.example.com"))],
        "Payment required",
    )
}
```
