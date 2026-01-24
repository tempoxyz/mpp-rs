# tower Middleware Example

Using `mpay` with [tower](https://docs.rs/tower) for reusable payment middleware.

## Dependencies

```toml
[dependencies]
mpay = "0.1"
tower = "0.4"
tower-http = "0.5"
http = "1"
pin-project-lite = "0.2"
```

## Payment Layer

```rust
use mpay::{Challenge, Credential, Receipt};
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

## Payment Service

```rust
use http::{Request, Response, StatusCode};

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
                if let Ok(credential) = Credential::from_authorization(auth_str) {
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
            .header("www-authenticate", challenge.to_www_authenticate(&self.config.realm))
            .body(ResBody::default())
            .unwrap();

        PaymentFuture::PaymentRequired(Some(response))
    }
}

impl<S> PaymentService<S> {
    fn create_challenge(&self) -> Challenge {
        Challenge {
            id: uuid::Uuid::new_v4().to_string(),
            method: self.config.method.clone(),
            intent: "charge".into(),
            request: serde_json::json!({
                "amount": self.config.amount,
                "asset": self.config.asset,
                "destination": self.config.destination,
            }),
        }
    }

    fn verify_payment(&self, credential: &Credential) -> bool {
        // Implement your verification logic
        true
    }
}
```

## Usage with axum

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

## Selective Application

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
