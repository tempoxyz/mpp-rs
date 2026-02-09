# Custom Payment Methods

This guide shows how to implement custom payment methods for mpay-rs.

## Design Overview

mpay-rs uses intent-specific traits that enforce shared schemas:

- **Intent** = Shared request schema (`ChargeRequest`, `AuthorizeRequest`)
- **Method** = Your implementation of an intent-specific trait (`ChargeMethod`)

All methods implementing the same intent use the same request type. This ensures consistent shapes and field names across all payment networks.

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
use mpay::{ChargeRequest, Receipt, PaymentCredential};
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

## Example: Multi-Chain EVM Method

Support multiple EVM chains with a single method:

```rust
use mpay::server::{ChargeMethod, VerificationError};
use mpay::{ChargeRequest, Receipt, PaymentCredential, PaymentPayload};
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
                .ok_or_else(|| VerificationError::from(format!("Unsupported chain: {}", chain_id)))?;

            let tx_hash = match &credential.payload {
                PaymentPayload::Hash { hash, .. } => hash.clone(),
                _ => return Err(VerificationError::from("Expected hash payload")),
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
use mpay::{PaymentChallenge, PaymentCredential, MppError};

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
    PaymentChallenge, PaymentCredential, ChargeRequest, Receipt,
    format_receipt, Base64UrlJson,
};
use mpay::server::{ChargeMethod, VerificationError};

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
            let credential = mpay::parse_authorization(auth)
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

    let www_auth = mpay::format_www_authenticate(&challenge).unwrap();

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

## Built-in: TempoChargeMethod

mpay-rs includes `TempoChargeMethod` for Tempo blockchain verification:

```rust
use mpay::server::{tempo_provider, TempoChargeMethod, ChargeMethod};
use mpay::ChargeRequest;

// Create provider and method
let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
let method = TempoChargeMethod::new(provider);

// The method name
assert_eq!(method.method(), "tempo");

// In your server handler:
let request = ChargeRequest {
    amount: "1000000".into(),
    currency: "0x20c0000000000000000000000000000000000000".into(),
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
