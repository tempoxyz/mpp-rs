# mpay

Rust SDK for the Machine Payments Protocol (MPP) - an implementation of the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ietf-httpauth-payment/).

## Design Principles

- **Protocol-first** — Core types (`Challenge`, `Credential`, `Receipt`) map directly to HTTP headers
- **Zero-copy parsing** — Efficient header parsing without unnecessary allocations
- **Pluggable methods** — Payment networks are feature-gated (Tempo included by default)
- **Minimal dependencies** — Core has minimal deps; features add what you need
- **Intent = Schema, Method = Implementation** — Intents define shared request schemas; methods implement verification

## Core Types

| Type | Role | HTTP Header |
|------|------|-------------|
| `PaymentChallenge` | Server's payment request | `WWW-Authenticate: Payment ...` |
| `ChargeRequest` | Typed request schema (inside challenge) | Base64 in `request=` param |
| `PaymentCredential` | Client's payment proof | `Authorization: Payment ...` |
| `PaymentReceipt` | Server's confirmation | `Payment-Receipt: ...` |

## Traits

| Trait | Side | Purpose |
|-------|------|---------|
| `ChargeMethod` | Server | Verify credentials against `ChargeRequest` |
| `PaymentProvider` | Client | Create credentials from challenges |

## Quick Start

### Parse a Challenge (Server → Client)

```rust
use mpay::Challenge;

let header = r#"Payment realm="api.example.com", id="abc123", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIn0""#;
let challenge = Challenge::from_www_authenticate(header)?;

println!("Method: {}", challenge.method);
println!("Intent: {}", challenge.intent);
```

### Create a Credential (Client → Server)

```rust
use mpay::Credential;

let credential = Credential {
    id: challenge.id.clone(),
    source: Some("did:pkh:eip155:8453:0x123...".into()),
    payload: serde_json::json!({"hash": "0xabc..."}),
};

let auth_header = credential.to_authorization();
```

### Parse a Receipt (Server → Client)

```rust
use mpay::Receipt;

let receipt = Receipt::from_payment_receipt(header)?;
assert_eq!(receipt.status, "success");
```

## API Reference

### Core

#### `Challenge`

A parsed payment challenge from a `WWW-Authenticate` header.

```rust
use mpay::Challenge;

let challenge = Challenge {
    id: "challenge-id".into(),
    method: "tempo".into(),
    intent: "charge".into(),
    request: serde_json::json!({"amount": "1000000", "currency": "0x...", "recipient": "0x..."}),
};

let header = challenge.to_www_authenticate("api.example.com");
let parsed = Challenge::from_www_authenticate(&header)?;
```

#### `Credential`

The credential sent in the `Authorization` header.

```rust
use mpay::Credential;

let credential = Credential {
    id: "challenge-id".into(),
    payload: serde_json::json!({"hash": "0x..."}),
    source: Some("did:pkh:eip155:1:0x...".into()),
};

let header = credential.to_authorization();
let parsed = Credential::from_authorization(&header)?;
```

#### `Receipt`

Payment receipt returned after successful verification.

```rust
use mpay::Receipt;

let receipt = Receipt {
    status: "success".into(),
    timestamp: Some("2024-01-20T12:00:00Z".into()),
    reference: Some("0x...".into()),
};

let header = receipt.to_payment_receipt();
let parsed = Receipt::from_payment_receipt(&header)?;
```

### Intent Schemas

Intent schemas define shared request fields per the IETF spec:

```rust
use mpay::Intent::ChargeRequest;

let request = ChargeRequest {
    amount: "1000000".into(),
    currency: "0x20c0000000000000000000000000000000000001".into(),
    recipient: Some("0x742d35Cc...".into()),
    expires: Some("2025-01-15T12:00:00Z".into()),
    ..Default::default()
};
```

### Server-Side Traits

Method traits verify payment credentials with typed schemas using alloy's Provider:

```rust
use mpay::server::{ChargeMethod, tempo};
use alloy::providers::ProviderBuilder;

// Create an alloy provider
let provider = ProviderBuilder::new()
    .connect_http("https://rpc.moderato.tempo.xyz".parse()?);

// Create the charge method with the provider
let method = tempo::ChargeMethod::new(provider);

// Verify a payment
let receipt = method.verify(&credential, &request).await?;
```

### Client-Side Traits

PaymentProvider creates credentials for challenges:

```rust
use mpay::client::{PaymentProvider, tempo};

let provider = tempo::Provider::new(signer, "https://rpc.moderato.tempo.xyz")?;

// Check support
assert!(provider.supports("tempo", "charge"));

// Create credential
let credential = provider.pay(&challenge).await?;
```

## Install

```toml
[dependencies]
mpay = "0.1"
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `client` | Client-side payment providers (`PaymentProvider` trait) |
| `server` | Server-side payment verification (`ChargeMethod` trait) |
| `tempo` | Tempo blockchain support (default, includes `evm`) |
| `evm` | Shared EVM utilities (Address, U256, parsing) |
| `http` | HTTP client support with `Fetch` extension trait (implies `client`) |
| `middleware` | reqwest-middleware support with `PaymentMiddleware` |

### Common configurations

```toml
# Server app
mpay = { version = "0.1", features = ["server", "tempo"] }

# Client app  
mpay = { version = "0.1", features = ["http", "tempo"] }

# Both sides
mpay = { version = "0.1", features = ["server", "http", "tempo"] }

# Core only (parsing/formatting)
mpay = { version = "0.1", default-features = false }
```

## HTTP Client Support

### Extension Trait (recommended)

Enable the `http` feature for the `Fetch` trait:

```rust
use mpay::client::{Fetch, tempo};

let provider = tempo::Provider::new(signer, "https://rpc.moderato.tempo.xyz")?;

let resp = client
    .get("https://api.example.com/paid")
    .send_with_payment(&provider)
    .await?;
```

### Middleware (automatic)

Enable the `middleware` feature for automatic 402 handling:

```rust
use mpay::client::{PaymentMiddleware, tempo};
use reqwest_middleware::ClientBuilder;

let provider = tempo::Provider::new(signer, "https://rpc.moderato.tempo.xyz")?;
let client = ClientBuilder::new(reqwest::Client::new())
    .with(PaymentMiddleware::new(provider))
    .build();
```

## Examples

See the [examples/](./examples/) directory for integration patterns with common HTTP libraries:

## Development

```bash
make build      # Build with default features (tempo)
make test       # Run tests
make check      # Format check, clippy, test, and build
make fix        # Auto-fix formatting and clippy warnings
```

## License

MIT OR Apache-2.0
