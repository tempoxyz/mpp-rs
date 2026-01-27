# Custom Intents and Methods

This guide shows how to implement custom payment intents and methods using `mpay`'s trait system.

## Overview

`mpay` provides two core traits:

- **`Intent`** (server-side): Verifies payment credentials against a request
- **`Method`** (client-side): Creates credentials to satisfy challenges

## Dependencies

```toml
[dependencies]
mpay = "0.1"
serde_json = "1"
tokio = { version = "1", features = ["full"] }
axum = "0.7"
chrono = "0.4"
```

## Intent Trait

Implement `Intent` for server-side payment verification:

```rust
use mpay::protocol::traits::{BoxFuture, Intent, VerificationError};
use mpay::protocol::core::{PaymentCredential, PaymentReceipt, ReceiptStatus, MethodName};

struct MyChargeIntent {
    rpc_url: String,
}

impl Intent for MyChargeIntent {
    fn name(&self) -> &str {
        "charge"
    }

    fn verify<'a>(
        &'a self,
        credential: &'a PaymentCredential,
        request: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<PaymentReceipt, VerificationError>> {
        Box::pin(async move {
            // 1. Parse the request
            let amount = request["amount"].as_str()
                .ok_or_else(|| VerificationError::Failed("missing amount".into()))?;
            let recipient = request["recipient"].as_str()
                .ok_or_else(|| VerificationError::Failed("missing recipient".into()))?;

            // 2. Verify the payment (check RPC, call API, etc.)
            let tx_hash = match &credential.payload {
                mpay::protocol::core::PaymentPayload::Hash { hash, .. } => hash.clone(),
                mpay::protocol::core::PaymentPayload::Transaction { .. } => {
                    return Err(VerificationError::Failed("expected hash payload".into()));
                }
            };

            // 3. Return a receipt on success
            Ok(PaymentReceipt {
                status: ReceiptStatus::Success,
                method: MethodName::from("my-method"),
                timestamp: chrono::Utc::now().to_rfc3339(),
                reference: tx_hash,
            })
        })
    }
}
```

## Stripe Intent Example

Custom intent for verifying Stripe payments:

```rust
use mpay::protocol::traits::{BoxFuture, Intent, VerificationError};
use mpay::protocol::core::{PaymentCredential, PaymentReceipt, ReceiptStatus, MethodName};

struct StripeChargeIntent {
    api_key: String,
    client: reqwest::Client,
}

impl StripeChargeIntent {
    fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::new(),
        }
    }
}

impl Intent for StripeChargeIntent {
    fn name(&self) -> &str {
        "charge"
    }

    fn verify<'a>(
        &'a self,
        credential: &'a PaymentCredential,
        request: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<PaymentReceipt, VerificationError>> {
        Box::pin(async move {
            // Extract payment_intent_id from credential payload
            let payload_json = serde_json::to_value(&credential.payload)
                .map_err(|e| VerificationError::Failed(e.to_string()))?;
            
            let payment_intent_id = payload_json["payment_intent_id"]
                .as_str()
                .ok_or_else(|| VerificationError::Failed("missing payment_intent_id".into()))?;

            // Verify with Stripe API
            let response = self.client
                .get(format!(
                    "https://api.stripe.com/v1/payment_intents/{}",
                    payment_intent_id
                ))
                .basic_auth(&self.api_key, None::<&str>)
                .send()
                .await
                .map_err(|e| VerificationError::Failed(e.to_string()))?;

            let payment_intent: serde_json::Value = response
                .json()
                .await
                .map_err(|e| VerificationError::Failed(e.to_string()))?;

            // Check status
            let status = payment_intent["status"].as_str().unwrap_or("");
            if status != "succeeded" {
                return Err(VerificationError::Failed(format!(
                    "Payment status: {}",
                    status
                )));
            }

            // Verify amount matches
            let paid_amount = payment_intent["amount"].as_u64().unwrap_or(0);
            let expected_amount: u64 = request["amount"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            if paid_amount != expected_amount {
                return Err(VerificationError::AmountMismatch {
                    expected: expected_amount.to_string(),
                    got: paid_amount.to_string(),
                });
            }

            Ok(PaymentReceipt {
                status: ReceiptStatus::Success,
                method: MethodName::from("stripe"),
                timestamp: chrono::Utc::now().to_rfc3339(),
                reference: payment_intent_id.to_string(),
            })
        })
    }
}
```

## Multi-Chain Intent

Verify payments across multiple EVM chains:

```rust
use mpay::protocol::traits::{BoxFuture, Intent, VerificationError};
use mpay::protocol::core::{PaymentCredential, PaymentReceipt, ReceiptStatus, MethodName};
use std::collections::HashMap;

struct MultiChainChargeIntent {
    rpc_urls: HashMap<u64, String>,
    client: reqwest::Client,
}

impl MultiChainChargeIntent {
    fn new() -> Self {
        let mut rpc_urls = HashMap::new();
        rpc_urls.insert(1, "https://eth.llamarpc.com".to_string());
        rpc_urls.insert(42161, "https://arb1.arbitrum.io/rpc".to_string());
        rpc_urls.insert(42431, "https://rpc.moderato.tempo.xyz".to_string());
        
        Self {
            rpc_urls,
            client: reqwest::Client::new(),
        }
    }

    async fn verify_on_chain(
        &self,
        chain_id: u64,
        tx_hash: &str,
    ) -> Result<bool, VerificationError> {
        let rpc_url = self.rpc_urls.get(&chain_id)
            .ok_or_else(|| VerificationError::Failed(format!(
                "unsupported chain: {}", chain_id
            )))?;

        let response: serde_json::Value = self.client
            .post(rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            }))
            .send()
            .await
            .map_err(|e| VerificationError::Failed(e.to_string()))?
            .json()
            .await
            .map_err(|e| VerificationError::Failed(e.to_string()))?;

        let status = response["result"]["status"].as_str().unwrap_or("0x0");
        Ok(status == "0x1")
    }
}

impl Intent for MultiChainChargeIntent {
    fn name(&self) -> &str {
        "charge"
    }

    fn verify<'a>(
        &'a self,
        credential: &'a PaymentCredential,
        request: &'a serde_json::Value,
    ) -> BoxFuture<'a, Result<PaymentReceipt, VerificationError>> {
        Box::pin(async move {
            // Parse chain_id from request
            let chain_id: u64 = request["methodDetails"]["chainId"]
                .as_u64()
                .unwrap_or(42431);

            // Get tx hash from credential
            let tx_hash = match &credential.payload {
                mpay::protocol::core::PaymentPayload::Hash { hash, .. } => hash.clone(),
                _ => return Err(VerificationError::Failed("expected hash".into())),
            };

            // Verify on the appropriate chain
            if !self.verify_on_chain(chain_id, &tx_hash).await? {
                return Err(VerificationError::TransactionFailed(
                    "transaction not successful".into()
                ));
            }

            Ok(PaymentReceipt {
                status: ReceiptStatus::Success,
                method: MethodName::from(match chain_id {
                    1 => "ethereum",
                    42161 => "arbitrum",
                    42431 => "tempo",
                    _ => "evm",
                }),
                timestamp: chrono::Utc::now().to_rfc3339(),
                reference: tx_hash,
            })
        })
    }
}
```

## Using Intents with axum

### Direct Usage

```rust
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    extract::State,
};
use mpay::protocol::core::{parse_authorization, format_www_authenticate, PaymentChallenge};
use mpay::protocol::traits::Intent;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    intent: Arc<dyn Intent>,
}

async fn paid_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Check for payment credential
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = parse_authorization(auth_str) {
                // Build request JSON from challenge echo
                let request: serde_json::Value = serde_json::from_str(
                    &mpay::Schema::base64url_decode(&credential.challenge.request).unwrap()
                ).unwrap();

                // Verify using the intent
                match state.intent.verify(&credential, &request).await {
                    Ok(receipt) => {
                        return (
                            StatusCode::OK,
                            [("payment-receipt", mpay::protocol::core::format_receipt(&receipt).unwrap())],
                            "Paid content",
                        ).into_response();
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("Payment verification failed: {}", e),
                        ).into_response();
                    }
                }
            }
        }
    }

    // Return 402 with challenge
    let challenge = PaymentChallenge {
        id: uuid::Uuid::new_v4().to_string(),
        realm: "api.example.com".into(),
        method: "tempo".into(),
        intent: "charge".into(),
        request: mpay::Schema::Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000000",
            "currency": "0x...",
            "recipient": "0x...",
        })).unwrap(),
        expires: None,
        description: None,
    };

    (
        StatusCode::PAYMENT_REQUIRED,
        [(header::WWW_AUTHENTICATE, format_www_authenticate(&challenge, "api.example.com").unwrap())],
        "Payment required",
    ).into_response()
}

async fn main() {
    let intent = StripeChargeIntent::new("sk_test_...".into());
    let state = AppState {
        intent: Arc::new(intent),
    };

    let app = axum::Router::new()
        .route("/paid", axum::routing::get(paid_endpoint))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Intent Registry

Use `IntentRegistry` for multiple intents:

```rust
use mpay::Intent::{IntentRegistry, Intent};
use std::sync::Arc;

fn setup_intents() -> IntentRegistry {
    let mut registry = IntentRegistry::new();
    
    // Register built-in Tempo intent
    registry.register(mpay::Method::tempo::TempoChargeIntent::new(
        "https://rpc.moderato.tempo.xyz"
    ).unwrap());
    
    // Register custom intents
    registry.register(StripeChargeIntent::new("sk_test_...".into()));
    registry.register(MultiChainChargeIntent::new());
    
    registry
}

async fn verify_payment(
    registry: &IntentRegistry,
    intent_name: &str,
    credential: &PaymentCredential,
    request: &serde_json::Value,
) -> Result<PaymentReceipt, VerificationError> {
    let intent = registry.get(intent_name)
        .ok_or_else(|| VerificationError::Failed(format!(
            "unknown intent: {}", intent_name
        )))?;
    
    intent.verify(credential, request).await
}
```

## Method Trait

Implement `Method` for client-side payment execution:

```rust
use mpay::protocol::traits::{BoxFuture, Intent, Method};
use mpay::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload, ChallengeEcho};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
struct StripeMethod {
    api_key: String,
    intents: HashMap<String, Arc<dyn Intent>>,
}

impl StripeMethod {
    fn new(api_key: String) -> Self {
        let mut intents: HashMap<String, Arc<dyn Intent>> = HashMap::new();
        intents.insert(
            "charge".into(),
            Arc::new(StripeChargeIntent::new(api_key.clone())),
        );
        
        Self { api_key, intents }
    }
}

impl Method for StripeMethod {
    fn name(&self) -> &str {
        "stripe"
    }

    fn intents(&self) -> &HashMap<String, Arc<dyn Intent>> {
        &self.intents
    }

    fn create_credential<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
    ) -> BoxFuture<'a, Result<PaymentCredential, mpay::MppError>> {
        Box::pin(async move {
            // Parse the request from the challenge
            let request: serde_json::Value = challenge.request.decode()?;
            let amount: u64 = request["amount"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| mpay::MppError::InvalidChallenge("missing amount".into()))?;

            // Create a Stripe PaymentIntent (you'd use the real Stripe SDK)
            let client = reqwest::Client::new();
            let response: serde_json::Value = client
                .post("https://api.stripe.com/v1/payment_intents")
                .basic_auth(&self.api_key, None::<&str>)
                .form(&[
                    ("amount", amount.to_string()),
                    ("currency", "usd".to_string()),
                    ("confirm", "true".to_string()),
                ])
                .send()
                .await
                .map_err(|e| mpay::MppError::Http(e.to_string()))?
                .json()
                .await
                .map_err(|e| mpay::MppError::Http(e.to_string()))?;

            let payment_intent_id = response["id"]
                .as_str()
                .ok_or_else(|| mpay::MppError::Http("no payment intent id".into()))?;

            // Build the credential
            let echo = ChallengeEcho {
                id: challenge.id.clone(),
                realm: challenge.realm.clone(),
                method: challenge.method.clone(),
                intent: challenge.intent.clone(),
                request: challenge.request.raw().to_string(),
                expires: challenge.expires.clone(),
            };

            Ok(PaymentCredential {
                challenge: echo,
                source: Some("stripe".into()),
                payload: PaymentPayload::hash(payment_intent_id),
            })
        })
    }
}
```

## Built-in TempoChargeIntent

`mpay` includes a built-in `TempoChargeIntent` for Tempo blockchain verification:

```rust
use mpay::Method::tempo::TempoChargeIntent;
use mpay::Intent::Intent;

// Create with default Tempo Moderato chain ID (42431)
let intent = TempoChargeIntent::new("https://rpc.moderato.tempo.xyz")?;

// Create with custom chain ID
let intent = TempoChargeIntent::with_chain_id(
    "https://rpc.mainnet.tempo.xyz",
    42430,  // Tempo Mainnet
)?;

// Use in verification
let receipt = intent.verify(&credential, &request).await?;
```

## Error Handling

`VerificationError` provides structured error types:

```rust
use mpay::Intent::VerificationError;

// Common verification errors
let err = VerificationError::NotFound("tx_0x123 not found".into());
let err = VerificationError::Expired("2024-01-01T00:00:00Z".into());
let err = VerificationError::AmountMismatch {
    expected: "1000000".into(),
    got: "500000".into(),
};
let err = VerificationError::RecipientMismatch {
    expected: "0xabc...".into(),
    got: "0xdef...".into(),
};
let err = VerificationError::TransactionFailed("reverted".into());
let err = VerificationError::Failed("custom error message".into());
```

All `VerificationError` variants can be converted to `MppError`:

```rust
let mpp_err: mpay::MppError = verification_error.into();
```
