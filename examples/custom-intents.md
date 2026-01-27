# Custom Intents

This guide shows how to implement custom payment intents and methods for mpay-rs.

## Overview

mpay-rs provides two core traits for extensibility:

- **`Intent`** (server-side): Verify payment credentials
- **`Method`** (client-side): Create payment credentials

Both follow a duck-typing pattern—implement the trait, and it just works.

## Intent Trait

The `Intent` trait is for server-side payment verification:

```rust
use mpay::Intent::{Intent, VerificationError};
use mpay::Receipt::PaymentReceipt;
use mpay::Credential::PaymentCredential;
use std::future::Future;

pub trait Intent: Clone + Send + Sync {
    /// The name of this intent (e.g., "charge")
    fn name(&self) -> &str;

    /// Verify a credential against a payment request
    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &serde_json::Value,
    ) -> impl Future<Output = Result<PaymentReceipt, VerificationError>> + Send;
}
```

## Method Trait

The `Method` trait is for client-side credential creation:

```rust
use mpay::Method::Method;
use mpay::Challenge::PaymentChallenge;
use mpay::Credential::PaymentCredential;
use mpay::MppError;
use std::future::Future;

pub trait Method: Clone + Send + Sync {
    /// The name of this method (e.g., "tempo", "stripe")
    fn name(&self) -> &str;

    /// Check if this method supports the given intent
    fn supports_intent(&self, intent: &str) -> bool;

    /// Create a credential for the given challenge
    fn create_credential(
        &self,
        challenge: &PaymentChallenge,
    ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send;
}
```

## Example: Stripe Intent

Here's a complete Stripe charge intent implementation:

```rust
use mpay::Intent::{Intent, VerificationError};
use mpay::Receipt::PaymentReceipt;
use mpay::Credential::PaymentCredential;

#[derive(Clone)]
pub struct StripeChargeIntent {
    api_key: String,
}

impl StripeChargeIntent {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
        }
    }
}

impl Intent for StripeChargeIntent {
    fn name(&self) -> &str {
        "charge"
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &serde_json::Value,
    ) -> impl std::future::Future<Output = Result<PaymentReceipt, VerificationError>> + Send {
        let api_key = self.api_key.clone();
        let credential = credential.clone();
        let request = request.clone();

        async move {
            // Extract payment intent ID from credential
            let payment_intent_id = &credential.payload.signature;

            // Verify with Stripe API
            let client = reqwest::Client::new();
            let resp = client
                .get(format!(
                    "https://api.stripe.com/v1/payment_intents/{}",
                    payment_intent_id
                ))
                .bearer_auth(&api_key)
                .send()
                .await
                .map_err(|e| VerificationError::new(format!("Stripe API error: {}", e)))?;

            if !resp.status().is_success() {
                return Err(VerificationError::not_found("Payment intent not found"));
            }

            let pi: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| VerificationError::new(format!("Invalid response: {}", e)))?;

            // Verify status
            let status = pi
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("");

            if status != "succeeded" {
                return Err(VerificationError::transaction_failed(format!(
                    "Payment not completed: status={}",
                    status
                )));
            }

            // Verify amount
            let expected_amount: i64 = request
                .get("amount")
                .and_then(|a| a.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            let actual_amount = pi
                .get("amount")
                .and_then(|a| a.as_i64())
                .unwrap_or(0);

            if actual_amount < expected_amount {
                return Err(VerificationError::invalid_amount(format!(
                    "Amount mismatch: expected {}, got {}",
                    expected_amount, actual_amount
                )));
            }

            Ok(PaymentReceipt::success("stripe", payment_intent_id))
        }
    }
}
```

## Example: Multi-Chain EVM Intent

Support multiple EVM chains with a single intent:

```rust
use mpay::Intent::{Intent, VerificationError};
use mpay::Receipt::PaymentReceipt;
use mpay::Credential::PaymentCredential;
use std::collections::HashMap;

#[derive(Clone)]
pub struct MultiChainIntent {
    rpc_urls: HashMap<u64, String>,
}

impl MultiChainIntent {
    pub fn new() -> Self {
        let mut rpc_urls = HashMap::new();
        rpc_urls.insert(1, "https://eth.llamarpc.com".into());
        rpc_urls.insert(8453, "https://base.llamarpc.com".into());
        rpc_urls.insert(42431, "https://rpc.moderato.tempo.xyz".into());
        Self { rpc_urls }
    }

    pub fn with_chain(mut self, chain_id: u64, rpc_url: impl Into<String>) -> Self {
        self.rpc_urls.insert(chain_id, rpc_url.into());
        self
    }

    async fn verify_on_chain(
        &self,
        chain_id: u64,
        tx_hash: &str,
        _request: &serde_json::Value,
    ) -> Result<PaymentReceipt, VerificationError> {
        let _rpc_url = self
            .rpc_urls
            .get(&chain_id)
            .ok_or_else(|| VerificationError::new(format!("Unsupported chain: {}", chain_id)))?;

        // Fetch and verify transaction receipt...
        // (Similar to TempoChargeIntent implementation)

        Ok(PaymentReceipt::success(
            format!("evm:{}", chain_id),
            tx_hash,
        ))
    }
}

impl Intent for MultiChainIntent {
    fn name(&self) -> &str {
        "charge"
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &serde_json::Value,
    ) -> impl std::future::Future<Output = Result<PaymentReceipt, VerificationError>> + Send {
        let this = self.clone();
        let credential = credential.clone();
        let request = request.clone();

        async move {
            // Extract chain ID from request
            let chain_id = request
                .get("methodDetails")
                .and_then(|md| md.get("chainId"))
                .and_then(|c| c.as_u64())
                .unwrap_or(1); // Default to Ethereum mainnet

            let tx_hash = &credential.payload.signature;
            this.verify_on_chain(chain_id, tx_hash, &request).await
        }
    }
}
```

## Using with Axum

Here's how to use custom intents with Axum:

```rust
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use mpay::{
    Challenge::{parse_www_authenticate, PaymentChallenge},
    Credential::{parse_authorization, PaymentCredential, format_authorization},
    Intent::{ChargeRequest, Intent, VerificationError},
    Receipt::{format_receipt, PaymentReceipt},
    Schema::Base64UrlJson,
};

// Application state with your intent
#[derive(Clone)]
struct AppState {
    intent: StripeChargeIntent,
}

// Verify payment or return challenge
async fn verify_or_challenge<I: Intent>(
    headers: &HeaderMap,
    intent: &I,
    request: &serde_json::Value,
    realm: &str,
) -> Result<(PaymentCredential, PaymentReceipt), Response> {
    // Check for Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(auth) => {
            // Parse and verify credential
            let credential = parse_authorization(auth)
                .map_err(|_| challenge_response(intent, request, realm))?;

            let receipt = intent
                .verify(&credential, request)
                .await
                .map_err(|e| error_response(e))?;

            Ok((credential, receipt))
        }
        None => Err(challenge_response(intent, request, realm)),
    }
}

fn challenge_response<I: Intent>(
    intent: &I,
    request: &serde_json::Value,
    realm: &str,
) -> Response {
    let challenge = PaymentChallenge {
        id: uuid::Uuid::new_v4().to_string(),
        realm: realm.into(),
        method: "stripe".into(),
        intent: intent.name().into(),
        request: Base64UrlJson::from_value(request).unwrap(),
        expires: None,
        description: None,
    };

    let www_auth = mpay::protocol::core::format_www_authenticate(&challenge).unwrap();

    (
        StatusCode::PAYMENT_REQUIRED,
        [("www-authenticate", www_auth)],
        "Payment required",
    )
        .into_response()
}

fn error_response(err: VerificationError) -> Response {
    (StatusCode::FORBIDDEN, err.to_string()).into_response()
}

// Protected endpoint
async fn paid_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Response> {
    let request = serde_json::json!({
        "amount": "1000", // $10.00 in cents
        "currency": "usd",
    });

    let (_credential, receipt) = verify_or_challenge(
        &headers,
        &state.intent,
        &request,
        "api.example.com",
    )
    .await?;

    // Payment verified! Return the resource
    let receipt_header = format_receipt(&receipt).unwrap();

    Ok((
        StatusCode::OK,
        [("payment-receipt", receipt_header)],
        "Premium content unlocked!",
    ))
}

// Router setup
fn app() -> Router {
    let state = AppState {
        intent: StripeChargeIntent::new("sk_test_..."),
    };

    Router::new()
        .route("/premium", get(paid_resource))
        .with_state(state)
}
```

## Built-in: TempoChargeIntent

mpay-rs includes `TempoChargeIntent` for Tempo blockchain verification:

```rust
use mpay::Method::tempo::TempoChargeIntent;
use mpay::Intent::Intent;

// Create intent
let intent = TempoChargeIntent::new("https://rpc.moderato.tempo.xyz")
    .with_timeout(30);

// In your server handler:
let receipt = intent.verify(&credential, &request).await?;
if receipt.is_success() {
    println!("Payment verified: {}", receipt.reference);
}
```

Features:
- Verifies both `hash` (pre-broadcast) and `transaction` (server-broadcast) credentials
- Validates transfer logs for ERC-20 tokens
- Checks expiration timestamps
- Confirms chain ID matches

## Custom Method Example

Here's a custom client-side method:

```rust
use mpay::Method::Method;
use mpay::Challenge::PaymentChallenge;
use mpay::Credential::{PaymentCredential, PaymentPayload};
use mpay::MppError;

#[derive(Clone)]
pub struct StripeMethod {
    api_key: String,
}

impl StripeMethod {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
        }
    }
}

impl Method for StripeMethod {
    fn name(&self) -> &str {
        "stripe"
    }

    fn supports_intent(&self, intent: &str) -> bool {
        matches!(intent, "charge" | "authorize")
    }

    fn create_credential(
        &self,
        challenge: &PaymentChallenge,
    ) -> impl std::future::Future<Output = Result<PaymentCredential, MppError>> + Send {
        let api_key = self.api_key.clone();
        let challenge = challenge.clone();

        async move {
            // Create a PaymentIntent with Stripe
            let client = reqwest::Client::new();
            let amount: i64 = challenge
                .request
                .decode_value()
                .ok()
                .and_then(|v| v.get("amount")?.as_str()?.parse().ok())
                .unwrap_or(0);

            let resp = client
                .post("https://api.stripe.com/v1/payment_intents")
                .bearer_auth(&api_key)
                .form(&[
                    ("amount", amount.to_string()),
                    ("currency", "usd".into()),
                    ("confirm", "true".into()),
                ])
                .send()
                .await
                .map_err(|e| MppError::Http(format!("Stripe error: {}", e)))?;

            let pi: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| MppError::Http(format!("Invalid response: {}", e)))?;

            let pi_id = pi
                .get("id")
                .and_then(|id| id.as_str())
                .ok_or_else(|| MppError::Http("Missing payment intent ID".into()))?;

            let echo = challenge.to_echo();
            Ok(PaymentCredential::new(
                echo,
                PaymentPayload::hash(pi_id), // Use hash type for Stripe PI ID
            ))
        }
    }
}
```

## Summary

| Trait | Side | Purpose |
|-------|------|---------|
| `Intent` | Server | Verify payment credentials |
| `Method` | Client | Create payment credentials |

Both traits are designed for:
- Zero registration overhead
- Full async/await support
- Clone + Send + Sync for concurrent use
- Easy composition with HTTP frameworks

See also:
- [axum-server.md](./axum-server.md) - Full Axum integration
- [reqwest-client.md](./reqwest-client.md) - Client-side usage
