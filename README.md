# mpp

[![Docs](https://img.shields.io/badge/docs-github%20pages-blue)](https://tempoxyz.github.io/mpp-rs)

Rust SDK for the Machine Payments Protocol (MPP) — an implementation of the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ietf-httpauth-payment/).

## Architecture

### Core Types

| Type | Role | HTTP Header |
|------|------|-------------|
| `PaymentChallenge` | Server's payment request | `WWW-Authenticate: Payment ...` |
| `ChargeRequest` | Typed request schema (inside challenge) | Base64 in `request=` param |
| `PaymentCredential` | Client's payment proof | `Authorization: Payment ...` |
| `Receipt` | Server's confirmation | `Payment-Receipt: ...` |

### Traits

| Trait | Side | Purpose |
|-------|------|---------|
| `ChargeMethod` | Server | Verify credentials against `ChargeRequest` |
| `PaymentProvider` | Client | Create credentials from challenges |

### Intents

Two built-in intent types:

- **`charge`** — One-time immediate payments (`ChargeRequest`)
- **`session`** — Pay-as-you-go streaming payments (`SessionRequest`)

Both support a `decimals` field for human-readable amounts (e.g., `"1.5"` with `decimals: 6` → `"1500000"`). The `decimals` field is input-only and stripped from wire serialization.

## Quick Start

### Server (simple API)

```rust
use mpp::server::{Mpp, tempo, TempoConfig};

let mpp = Mpp::create(tempo(TempoConfig {
    currency: "0x20c0000000000000000000000000000000000000",
    recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
}))?;

let challenge = mpp.charge("1")?;
let receipt = mpp.verify_credential(&credential).await?;
```

### Server (advanced API)

```rust
use mpp::server::{Mpp, tempo_provider, TempoChargeMethod};

let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
let method = TempoChargeMethod::new(provider);
let payment = Mpp::new(method, "api.example.com", "my-server-secret");

let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
let receipt = payment.verify(&credential, &request).await?;
```

### Client (extension trait)

```rust
use mpp::client::{Fetch, TempoProvider};

let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
let resp = client.get(url).send_with_payment(&provider).await?;
```

### Client (middleware)

```rust
use mpp::client::{PaymentMiddleware, TempoProvider};
use reqwest_middleware::ClientBuilder;

let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
let client = ClientBuilder::new(reqwest::Client::new())
    .with(PaymentMiddleware::new(provider))
    .build();
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `client` | Client-side payment providers (`PaymentProvider` trait, `Fetch` extension) |
| `server` | Server-side payment verification (`ChargeMethod` trait) |
| `tempo` | Tempo blockchain support (includes `evm`) |
| `evm` | Shared EVM utilities (Address, U256, parsing) |
| `middleware` | reqwest-middleware support with `PaymentMiddleware` (implies `client`) |
| `utils` | Hex/random utilities for development and testing |

The `tempo` feature requires a git patch:

```toml
[patch.crates-io]
tempo-alloy = { git = "https://github.com/tempoxyz/tempo" }
tempo-primitives = { git = "https://github.com/tempoxyz/tempo" }
```

## Commands

```bash
make build      # Build with default features (tempo)
make test       # Run tests
make check      # Format check, clippy, test, and build
make fix        # Auto-fix formatting and clippy warnings
```

## License

MIT OR Apache-2.0
