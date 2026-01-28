# Middleware Examples

Using `mpay` with middleware for automatic 402 handling.

## Client-Side: reqwest-middleware

With the `middleware` feature, use `PaymentMiddleware` for automatic 402
handling on all requests.

### Dependencies

```toml
[dependencies]
mpay = { version = "0.1", features = ["middleware", "tempo"] }
reqwest = { version = "0.12", features = ["json"] }
reqwest-middleware = "0.4"
tokio = { version = "1", features = ["full"] }
```

### Usage

```rust
use mpay::client::{PaymentMiddleware, TempoProvider};
use mpay::PrivateKeySigner;  // Requires `evm` or `tempo` feature
use reqwest_middleware::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up your signer
    let signer = PrivateKeySigner::random();
    
    // Create a Tempo payment provider
    let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
    
    // Build client with payment middleware
    let client = ClientBuilder::new(reqwest::Client::new())
        .with(PaymentMiddleware::new(provider))
        .build();
    
    // All requests automatically handle 402 responses
    let resp = client
        .get("https://api.example.com/paid-resource")
        .send()
        .await?;
    
    println!("Status: {}", resp.status());
    println!("Body: {}", resp.text().await?);
    
    Ok(())
}
```

### Comparison: Middleware vs Extension Trait

| Approach | Pros | Cons |
|----------|------|------|
| `PaymentMiddleware` | Automatic for all requests | Less control per-request |
| `Fetch` trait | Opt-in per request | Must call `.send_with_payment()` |

Use **middleware** when you want all requests to automatically pay.
Use **extension trait** when you want explicit control over which requests pay.

---

## Server-Side: tower Layer

For server-side payment requirements using [tower](https://docs.rs/tower).

### Dependencies

```toml
[dependencies]
mpay = "0.1"
tower = "0.4"
tower-http = "0.5"
http = "1"
axum = "0.7"
```

### Payment Layer

```rust
use mpay::{PaymentChallenge, PaymentCredential, parse_authorization};
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Configuration for payment requirements
#[derive(Clone)]
pub struct PaymentConfig {
    pub realm: String,
    pub method: String,
    pub amount: String,
    pub asset: String,
    pub destination: String,
}

/// Tower Layer that wraps services with payment requirements
#[derive(Clone)]
pub struct PaymentLayer {
    config: PaymentConfig,
}

impl PaymentLayer {
    pub fn new(config: PaymentConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for PaymentLayer {
    type Service = PaymentService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PaymentService {
            inner,
            config: self.config.clone(),
        }
    }
}
```

### Payment Service

```rust
use http::{Request, Response, StatusCode};
use mpay::{PaymentChallenge, PaymentCredential, Base64UrlJson, parse_authorization, format_www_authenticate};

#[derive(Clone)]
pub struct PaymentService<S> {
    inner: S,
    config: PaymentConfig,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for PaymentService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = PaymentFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Check for valid payment credential
        if let Some(auth) = req.headers().get("authorization") {
            if let Ok(auth_str) = auth.to_str() {
                if let Ok(credential) = parse_authorization(auth_str) {
                    if self.verify_payment(&credential) {
                        // Payment valid - proceed to inner service
                        return PaymentFuture::Authorized(self.inner.call(req));
                    }
                }
            }
        }

        // No valid payment - return 402
        let challenge = self.create_challenge();
        let response = Response::builder()
            .status(StatusCode::PAYMENT_REQUIRED)
            .header("www-authenticate", format_www_authenticate(&challenge).unwrap())
            .body(ResBody::default())
            .unwrap();

        PaymentFuture::PaymentRequired(Some(response))
    }
}

impl<S> PaymentService<S> {
    fn create_challenge(&self) -> PaymentChallenge {
        PaymentChallenge {
            id: uuid::Uuid::new_v4().to_string(),
            realm: self.config.realm.clone(),
            method: self.config.method.clone().into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": self.config.amount,
                "currency": self.config.asset,
                "recipient": self.config.destination,
            })).unwrap(),
            expires: None,
            description: None,
        }
    }

    fn verify_payment(&self, credential: &PaymentCredential) -> bool {
        // Implement your verification logic:
        // 1. Check transaction hash on-chain
        // 2. Verify amount matches
        // 3. Verify recipient matches
        true
    }
}
```

### Usage with axum

```rust
use axum::{routing::get, Router};
use tower::ServiceBuilder;

let payment_config = PaymentConfig {
    realm: "api.example.com".into(),
    method: "tempo".into(),
    amount: "1000000".into(),
    asset: "0x...".into(),
    destination: "0x...".into(),
};

let app = Router::new()
    .route("/paid", get(handler))
    .layer(ServiceBuilder::new().layer(PaymentLayer::new(payment_config)));
```

### Selective Application

```rust
let free_routes = Router::new()
    .route("/health", get(health))
    .route("/docs", get(docs));

let paid_routes = Router::new()
    .route("/api/data", get(get_data))
    .route("/api/compute", post(compute))
    .layer(PaymentLayer::new(config));

let app = Router::new()
    .merge(free_routes)
    .merge(paid_routes);
```
