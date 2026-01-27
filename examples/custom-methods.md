# Custom Payment Methods

This guide shows how to implement custom payment methods for mpay-rs.

## Design Overview

mpay-rs uses intent-specific traits that enforce shared schemas:

- **Intent** = Shared request schema (`ChargeRequest`, `AuthorizeRequest`)
- **Method** = Your implementation of an intent-specific trait (`ChargeMethod`)

All methods implementing the same intent use the same request type. This ensures consistent field names (amount, currency, recipient) across all payment networks.

### Core Traits

| Trait | Side | Purpose |
|-------|------|---------|
| `ChargeMethod` | Server | Verify one-time payment credentials |
| `AuthorizeMethod` | Server | Verify authorization + capture |
| `PaymentProvider` | Client | Create payment credentials |

## Server-Side: ChargeMethod

The `ChargeMethod` trait verifies payment credentials against a typed `ChargeRequest`:

```rust
use mpay::server::{ChargeMethod, VerificationError};
use mpay::Intent::ChargeRequest;
use mpay::Receipt::Receipt;
use mpay::Credential::PaymentCredential;
use std::future::Future;

pub trait ChargeMethod: Clone + Send + Sync {
    /// Payment method identifier (e.g., "tempo", "stripe")
    fn method(&self) -> &str;

    /// Verify a charge credential against the typed request
    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send;
}
```

## Example: Stripe ChargeMethod

```rust
use mpay::server::{ChargeMethod, VerificationError};
use mpay::Intent::ChargeRequest;
use mpay::Receipt::Receipt;
use mpay::Credential::PaymentCredential;

#[derive(Clone)]
pub struct StripeChargeMethod {
    api_key: String,
}

impl StripeChargeMethod {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self { api_key: api_key.into() }
    }
}

impl ChargeMethod for StripeChargeMethod {
    fn method(&self) -> &str {
        "stripe"
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl std::future::Future<Output = Result<Receipt, VerificationError>> + Send {
        let api_key = self.api_key.clone();
        let credential = credential.clone();
        let request = request.clone();

        async move {
            // Extract payment intent ID from credential payload
            let payment_intent_id = match &credential.payload {
                mpay::Credential::PaymentPayload::Hash { hash, .. } => hash.clone(),
                _ => return Err(VerificationError::new("Expected hash payload")),
            };

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
            let status = pi.get("status").and_then(|s| s.as_str()).unwrap_or("");
            if status != "succeeded" {
                return Err(VerificationError::transaction_failed(format!(
                    "Payment not completed: status={}",
                    status
                )));
            }

            // Verify amount using typed ChargeRequest
            let expected_amount: i64 = request.amount.parse().unwrap_or(0);
            let actual_amount = pi.get("amount").and_then(|a| a.as_i64()).unwrap_or(0);

            if actual_amount < expected_amount {
                return Err(VerificationError::invalid_amount(format!(
                    "Amount mismatch: expected {}, got {}",
                    expected_amount, actual_amount
                )));
            }

            Ok(Receipt::success("stripe", &payment_intent_id))
        }
    }
}
```

## Example: Multi-Chain EVM Method

Support multiple EVM chains with a single method:

```rust
use mpay::server::{ChargeMethod, VerificationError};
use mpay::Intent::ChargeRequest;
use mpay::Receipt::Receipt;
use mpay::Credential::PaymentCredential;
use std::collections::HashMap;

#[derive(Clone)]
pub struct MultiChainChargeMethod {
    rpc_urls: HashMap<u64, String>,
}

impl MultiChainChargeMethod {
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

    fn get_chain_id(request: &ChargeRequest) -> u64 {
        request
            .method_details
            .as_ref()
            .and_then(|md| md.get("chainId"))
            .and_then(|c| c.as_u64())
            .unwrap_or(1) // Default to Ethereum mainnet
    }
}

impl ChargeMethod for MultiChainChargeMethod {
    fn method(&self) -> &str {
        "evm"
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl std::future::Future<Output = Result<Receipt, VerificationError>> + Send {
        let this = self.clone();
        let credential = credential.clone();
        let request = request.clone();

        async move {
            let chain_id = Self::get_chain_id(&request);

            let _rpc_url = this
                .rpc_urls
                .get(&chain_id)
                .ok_or_else(|| VerificationError::new(format!("Unsupported chain: {}", chain_id)))?;

            let tx_hash = match &credential.payload {
                mpay::Credential::PaymentPayload::Hash { hash, .. } => hash.clone(),
                _ => return Err(VerificationError::new("Expected hash payload")),
            };

            // Verify transaction on chain using request.amount, request.currency, request.recipient
            // (implementation similar to TempoChargeMethod)

            Ok(Receipt::success(format!("evm:{}", chain_id), &tx_hash))
        }
    }
}
```

## Client-Side: PaymentProvider

The `PaymentProvider` trait creates credentials for payment challenges:

```rust
use mpay::client::PaymentProvider;
use mpay::Challenge::PaymentChallenge;
use mpay::Credential::PaymentCredential;
use mpay::MppError;

pub trait PaymentProvider: Clone + Send + Sync {
    /// Check if this provider supports the method+intent combination
    fn supports(&self, method: &str, intent: &str) -> bool;

    /// Create a credential for the challenge
    fn pay(
        &self,
        challenge: &PaymentChallenge,
    ) -> impl std::future::Future<Output = Result<PaymentCredential, MppError>> + Send;
}
```

### Example: Stripe Provider

With Stripe, the server creates a PaymentIntent and includes its ID in the challenge's
`method_details`. The client confirms the payment and returns the ID as the credential:

```rust
use mpay::client::PaymentProvider;
use mpay::Challenge::PaymentChallenge;
use mpay::Credential::{PaymentCredential, PaymentPayload};
use mpay::MppError;

#[derive(Clone)]
pub struct StripeProvider {
    publishable_key: String,
}

impl StripeProvider {
    pub fn new(publishable_key: impl Into<String>) -> Self {
        Self { publishable_key: publishable_key.into() }
    }
}

impl PaymentProvider for StripeProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == "stripe" && matches!(intent, "charge" | "authorize")
    }

    fn pay(
        &self,
        challenge: &PaymentChallenge,
    ) -> impl std::future::Future<Output = Result<PaymentCredential, MppError>> + Send {
        let challenge = challenge.clone();

        async move {
            // Server provides the PaymentIntent ID in method_details
            let request: serde_json::Value = challenge.request.decode()?;
            let pi_id = request
                .get("method_details")
                .and_then(|md| md.get("payment_intent_id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| MppError::Http("Missing payment_intent_id in challenge".into()))?;

            // Client would confirm the PaymentIntent via Stripe.js in a real implementation.
            // Here we just return the ID as proof of payment.

            let echo = challenge.to_echo();
            Ok(PaymentCredential::new(echo, PaymentPayload::hash(pi_id)))
        }
    }
}
```


## Using with Axum

Here's how to use ChargeMethod with Axum:

```rust
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use mpay::{
    Challenge::PaymentChallenge,
    Credential::PaymentCredential,
    Intent::ChargeRequest,
    server::{ChargeMethod, VerificationError},
    Receipt::{format_receipt, Receipt},
    Schema::Base64UrlJson,
};

#[derive(Clone)]
struct AppState<M: ChargeMethod> {
    method: M,
}

async fn verify_or_challenge<M: ChargeMethod>(
    headers: &HeaderMap,
    method: &M,
    request: &ChargeRequest,
    realm: &str,
) -> Result<(PaymentCredential, Receipt), Response> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(auth) => {
            let credential = mpay::Credential::format_authorization
                .parse(auth)
                .map_err(|_| challenge_response(method, request, realm))?;

            let receipt = method
                .verify(&credential, request)
                .await
                .map_err(|e| error_response(e))?;

            Ok((credential, receipt))
        }
        None => Err(challenge_response(method, request, realm)),
    }
}

fn challenge_response<M: ChargeMethod>(
    method: &M,
    request: &ChargeRequest,
    realm: &str,
) -> Response {
    let challenge = PaymentChallenge {
        id: uuid::Uuid::new_v4().to_string(),
        realm: realm.into(),
        method: method.method().into(),
        intent: "charge".into(),
        request: Base64UrlJson::from_value(&serde_json::to_value(request).unwrap()).unwrap(),
        expires: None,
        description: None,
    };

    let www_auth = mpay::protocol::core::format_www_authenticate(&challenge).unwrap();

    (
        StatusCode::PAYMENT_REQUIRED,
        [("www-authenticate", www_auth)],
        "Payment required",
    ).into_response()
}

fn error_response(err: VerificationError) -> Response {
    (StatusCode::FORBIDDEN, err.to_string()).into_response()
}

async fn paid_resource<M: ChargeMethod>(
    State(state): State<AppState<M>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Response> {
    let request = ChargeRequest {
        amount: "1000".into(), // $10.00 in cents
        currency: "usd".into(),
        ..Default::default()
    };

    let (_credential, receipt) = verify_or_challenge(
        &headers,
        &state.method,
        &request,
        "api.example.com",
    ).await?;

    let receipt_header = format_receipt(&receipt).unwrap();
    Ok((
        StatusCode::OK,
        [("payment-receipt", receipt_header)],
        "Premium content unlocked!",
    ))
}
```

## Built-in: tempo::ChargeMethod

mpay-rs includes `tempo::ChargeMethod` for Tempo blockchain verification:

```rust
use mpay::server::tempo::ChargeMethod;
use mpay::Intent::ChargeRequest;

let method = ChargeMethod::new("https://rpc.moderato.tempo.xyz")
    .with_timeout(30);

// The method name
assert_eq!(method.method(), "tempo");

// In your server handler:
let request = ChargeRequest {
    amount: "1000000".into(),
    currency: "0x20c0000000000000000000000000000000000001".into(),
    recipient: Some("0x742d35Cc...".into()),
    ..Default::default()
};

let receipt = method.verify(&credential, &request).await?;
if receipt.is_success() {
    println!("Payment verified: {}", receipt.reference);
}
```

Features:
- Verifies `hash` (pre-broadcast) and `transaction` (server-broadcast) credentials
- Validates ERC-20 transfer logs
- Checks expiration timestamps
- Confirms chain ID matches

## Summary

| Concept | Description |
|---------|-------------|
| **Intent** | Shared schema (e.g., `ChargeRequest`) |
| **Method** | Implementation of intent trait (e.g., `StripeChargeMethod`) |
| **Provider** | Client-side credential creation |

This design ensures:
- Consistent field names across all payment methods
- Type safety for request parameters
- Clear separation between schema (intent) and implementation (method)

See also:
- [axum-server.md](./axum-server.md) - Full Axum integration
- [reqwest-client.md](./reqwest-client.md) - Client-side usage
