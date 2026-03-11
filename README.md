# mpp

Rust SDK for the [**Machine Payments Protocol**](https://mpp.dev)

[![Docs](https://img.shields.io/badge/docs-github%20pages-blue)](https://tempoxyz.github.io/mpp-rs)
[![License](https://img.shields.io/crates/l/mpp.svg)](LICENSE)

## Documentation

Full documentation, API reference, and guides are available at **[mpp.dev/sdk/rust](https://mpp.dev/sdk/rust)**.

## Install

```bash
cargo add mpp
```

## Quick Start

### Server

```rust
use mpp::server::{Mpp, tempo, TempoConfig};

let mpp = Mpp::create(tempo(TempoConfig {
    recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
}))?;

let challenge = mpp.charge("1")?;
let receipt = mpp.verify_credential(&credential).await?;
```

### Client

```rust
use mpp::client::{PaymentMiddleware, TempoProvider};
use reqwest_middleware::ClientBuilder;

let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
let client = ClientBuilder::new(reqwest::Client::new())
    .with(PaymentMiddleware::new(provider))
    .build();

// Requests now handle 402 automatically
let resp = client.get("https://mpp.dev/api/ping/paid").send().await?;
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

## Protocol

Built on the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ryan-httpauth-payment/). See [mpp-specs](https://tempoxyz.github.io/mpp-specs/) for the full specification.

## License

MIT OR Apache-2.0
