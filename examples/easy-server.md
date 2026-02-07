# Easy Server Example

Simplified axum server using `Mpay::create(tempo(...))`.

## Before (verbose API)

```rust
use mpay::server::{tempo_provider, Mpay, TempoChargeMethod};
use mpay::{parse_authorization, ChargeRequest};

let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
let method = TempoChargeMethod::new(provider);
let payment = Mpay::new(method, "api.example.com", "my-server-secret");

// Every charge call needs amount in base units, currency, AND recipient
let challenge = payment.charge_challenge("1000000", ALPHA_USD, MERCHANT)?;
```

## After (simple API)

```rust
use mpay::server::{Mpay, tempo, TempoConfig};

let mpay = Mpay::create(tempo(TempoConfig {
    currency: "0x20c0000000000000000000000000000000000001",
    recipient: "0xabc...123",
}))?;

// Just the dollar amount — currency, recipient, realm, secret, expires
// are all handled automatically
let challenge = mpay.charge("0.10")?;
```

## Full axum example

```rust
use axum::{extract::State, http::{header, HeaderMap, StatusCode}, response::IntoResponse, routing::get, Router};
use mpay::server::{Mpay, tempo, TempoConfig};
use mpay::parse_authorization;
use std::sync::Arc;

type Payment = Mpay<mpay::server::TempoChargeMethod<mpay::server::TempoProvider>>;

#[tokio::main]
async fn main() {
    let mpay = Mpay::create(
        tempo(TempoConfig {
            currency: "0x20c0000000000000000000000000000000000001",
            recipient: "0xabc...123",
        })
        .secret_key("my-server-secret")
        .realm("api.example.com"),
    )
    .expect("failed to create payment handler");

    let app = Router::new()
        .route("/paid", get(paid_endpoint))
        .with_state(Arc::new(mpay));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn paid_endpoint(
    State(mpay): State<Arc<Payment>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        if let Ok(credential) = parse_authorization(auth) {
            if let Ok(receipt) = mpay.verify_credential(&credential).await {
                return (
                    StatusCode::OK,
                    [("payment-receipt", receipt.to_header().unwrap())],
                    "Paid content!",
                ).into_response();
            }
        }
    }

    let challenge = mpay.charge("0.10").unwrap();
    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, challenge.to_header().unwrap())],
        "Payment required",
    ).into_response()
}
```

## What changed

| Before | After |
|--------|-------|
| `tempo_provider(url)` + `TempoChargeMethod::new(p)` + `Mpay::new(m, realm, secret)` | `Mpay::create(tempo(TempoConfig { currency, recipient }))` |
| `charge_challenge("1000000", currency, recipient)` | `charge("0.10")` |
| Manual `ChargeRequest` construction for verify | `verify_credential(&credential)` — request decoded automatically |
| Must specify realm, secret_key, RPC URL | Smart defaults (override with builder methods) |
| Amount in base units (attos/wei) | Amount in dollars |
