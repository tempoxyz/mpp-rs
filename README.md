# mpay

Rust SDK for the Machine Payments Protocol (MPP) - an implementation of the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ietf-httpauth-payment/).

## Design Principles

- **Protocol-first** — Core types (`Challenge`, `Credential`, `Receipt`) map directly to HTTP headers
- **Zero-copy parsing** — Efficient header parsing without unnecessary allocations
- **Pluggable methods** — Payment networks are feature-gated
- **Minimal dependencies** — Core has minimal deps; features add what you need
- **Intent = Schema, Method = Implementation** — Intents define shared request schemas; methods implement verification

## Core Types

| Type | Role | HTTP Header |
|------|------|-------------|
| `PaymentChallenge` | Server's payment request | `WWW-Authenticate: Payment ...` |
| `ChargeRequest` | Typed request schema (inside challenge) | Base64 in `request=` param |
| `PaymentCredential` | Client's payment proof | `Authorization: Payment ...` |
| `Receipt` | Server's confirmation | `Payment-Receipt: ...` |

## Traits

| Trait | Side | Purpose |
|-------|------|---------|
| `ChargeMethod` | Server | Verify credentials against `ChargeRequest` |
| `PaymentProvider` | Client | Create credentials from challenges |

## Quick Start

### Parse a Challenge (Server → Client)

```rust
use mpay::{parse_www_authenticate, PaymentChallenge};

let header = r#"Payment realm="api.example.com", id="abc123", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIn0""#;
let challenge = parse_www_authenticate(header)?;

println!("Method: {}", challenge.method);
println!("Intent: {}", challenge.intent);
```

### Create a Credential (Client → Server)

```rust
use mpay::{PaymentCredential, PaymentPayload, format_authorization};

// After parsing a challenge, create a credential with the echo
let credential = PaymentCredential::with_source(
    challenge.to_echo(),  // Echo the challenge parameters
    "did:pkh:eip155:8453:0x123...",
    PaymentPayload::hash("0xabc..."),
);

let auth_header = format_authorization(&credential)?;
```

### Parse a Receipt (Server → Client)

```rust
use mpay::{parse_receipt, Receipt};

let receipt = parse_receipt(header)?;
assert!(receipt.is_success());
```

## API Reference

### Core

#### `PaymentChallenge`

A parsed payment challenge from a `WWW-Authenticate` header.

```rust
use mpay::{PaymentChallenge, Base64UrlJson, format_www_authenticate, parse_www_authenticate};

let challenge = PaymentChallenge {
    id: "challenge-id".into(),
    realm: "api.example.com".into(),
    method: "tempo".into(),
    intent: "charge".into(),
    request: Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"}))?,
    expires: None,
    description: None,
};

let header = format_www_authenticate(&challenge)?;
let parsed = parse_www_authenticate(&header)?;
```

#### `PaymentCredential`

The credential sent in the `Authorization` header.

```rust
use mpay::{PaymentCredential, PaymentPayload, format_authorization, parse_authorization};

// After parsing a challenge, create the credential
let credential = PaymentCredential::with_source(
    challenge.to_echo(),  // Echo the parsed challenge
    "did:pkh:eip155:1:0x...",
    PaymentPayload::hash("0x..."),
);

let header = format_authorization(&credential)?;
let parsed = parse_authorization(&header)?;
```

#### `Receipt`

Payment receipt returned after successful verification.

```rust
use mpay::{Receipt, format_receipt, parse_receipt};

let receipt = Receipt::success("tempo", "0x...");

// Format using standalone function
let header = format_receipt(&receipt)?;

// Or use the method directly
let header = receipt.to_header()?;

let parsed = parse_receipt(&header)?;
```

### Intent Schemas

Intent schemas define shared request fields per spec:

```rust
use mpay::ChargeRequest;

let request = ChargeRequest {
    amount: "1000000".into(),
    currency: "0x20c0000000000000000000000000000000000000".into(),
    recipient: Some("0x742d35Cc...".into()),
    expires: Some("2025-01-15T12:00:00Z".into()),
    ..Default::default()
};
```

### Server-Side Handler

Use `Mpay` to bind method, realm, and secret_key once:

```rust
use mpay::server::{Mpay, tempo_provider, TempoChargeMethod};

// Create provider and method
let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
let method = TempoChargeMethod::new(provider);

// Create handler with bound secret_key
let payment = Mpay::new(method, "api.example.com", "my-server-secret");

// Generate challenge (secretKey already bound)
let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;

// Verify a payment
let receipt = payment.verify(&credential, &request).await?;
```

### Client-Side Traits

PaymentProvider creates credentials for challenges:

```rust
use mpay::client::{PaymentProvider, TempoProvider};

let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;

// Check support
assert!(provider.supports("tempo", "charge"));

// Create credential
let credential = provider.pay(&challenge).await?;
```

### Multiple Payment Methods

Use `MultiProvider` to handle multiple payment methods:

```rust
use mpay::client::{MultiProvider, TempoProvider};

let provider = MultiProvider::new()
    .with(TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?);
    // .with(StripeProvider::new(api_key))
    // .with(OtherProvider::new(...))

// Automatically picks the right provider based on challenge.method
let resp = client.get(url).send_with_payment(&provider).await?;
```

## Install

```toml
[dependencies]
mpay = "0.2"
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `client` | Client-side payment providers (`PaymentProvider` trait, `Fetch` extension) |
| `server` | Server-side payment verification (`ChargeMethod` trait) |
| `tempo` | Tempo blockchain support (includes `evm`) - requires git patch (see below) |
| `evm` | Shared EVM utilities (Address, U256, parsing) |
| `http` | HTTP client support with `Fetch` extension trait (implies `client`). For Tempo payments, combine with `tempo`: `features = ["http", "tempo"]` |
| `middleware` | reqwest-middleware support with `PaymentMiddleware` (implies `client`) |
| `utils` | Hex/random utilities for development and testing |

### Common configurations

```toml
# Core only (parsing/formatting) - works out of the box
mpay = "0.2"

# With Tempo support (requires git patch)
mpay = { version = "0.2", features = ["tempo"] }

# Server app with Tempo
mpay = { version = "0.2", features = ["server", "tempo"] }

# Client app with Tempo
mpay = { version = "0.2", features = ["client", "tempo"] }
```

### Using the `tempo` feature

The `tempo` feature requires Tempo's internal crates which are not published to crates.io.
Add this patch to your `Cargo.toml`:

```toml
[patch.crates-io]
tempo-alloy = { git = "https://github.com/tempoxyz/tempo" }
tempo-primitives = { git = "https://github.com/tempoxyz/tempo" }
```

## HTTP Client Support

### Extension Trait (recommended)

Enable the `client` feature for the `Fetch` trait:

```rust
use mpay::client::{Fetch, TempoProvider};

let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;

let resp = client
    .get("https://api.example.com/paid")
    .send_with_payment(&provider)
    .await?;
```

### Middleware (automatic)

Enable the `middleware` feature for automatic 402 handling:

```rust
use mpay::client::{PaymentMiddleware, TempoProvider};
use reqwest_middleware::ClientBuilder;

let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
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
