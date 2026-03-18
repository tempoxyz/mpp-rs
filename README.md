<br>
<br>

<p align="center">
  <a href="https://mpp.dev">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/tempoxyz/mpp/refs/heads/main/public/lockup-light.svg">
      <img alt="Machine Payments Protocol" src="https://raw.githubusercontent.com/tempoxyz/mpp/refs/heads/main/public/lockup-dark.svg" width="auto" height="120">
    </picture>
  </a>
</p>

<br>
<br>

# mpp

Rust SDK for the [**Machine Payments Protocol**](https://mpp.dev)

[![Website](https://img.shields.io/badge/website-mpp.dev-black)](https://mpp.dev)
[![Docs](https://img.shields.io/badge/docs-mpp.dev-blue)](https://mpp.dev/sdk/rust)
[![Crates.io](https://img.shields.io/crates/v/mpp.svg)](https://crates.io/crates/mpp)
[![License](https://img.shields.io/crates/l/mpp.svg)](LICENSE-MIT)

[MPP](https://mpp.dev) lets any client — agents, apps, or humans — pay for any service in the same HTTP request. It standardizes [HTTP 402](https://mpp.dev/protocol/http-402) with an open [IETF specification](https://paymentauth.org), so servers can charge and clients can pay without API keys, billing accounts, or checkout flows.

You can get started today by reading the [Rust SDK docs](https://mpp.dev/sdk/rust), exploring the [protocol overview](https://mpp.dev/protocol/), or jumping straight to the [quickstart](https://mpp.dev/quickstart/).

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
| `tempo` | [Tempo](https://tempo.xyz) blockchain support (includes `evm`) |
| `evm` | Shared EVM utilities (Address, U256, parsing) |
| `middleware` | reqwest-middleware support with `PaymentMiddleware` (implies `client`) |
| `tower` | Tower middleware for server-side integration |
| `axum` | Axum extractor support for server-side convenience |
| `utils` | Hex/random utilities for development and testing |

## Payment Methods

MPP supports multiple [payment methods](https://mpp.dev/payment-methods/) through one protocol — [Tempo](https://mpp.dev/payment-methods/tempo/), [Stripe](https://mpp.dev/payment-methods/stripe/), [Lightning](https://mpp.dev/payment-methods/lightning/), [Card](https://mpp.dev/payment-methods/card/), and [custom methods](https://mpp.dev/payment-methods/custom). The server advertises which methods it accepts, and the client chooses which one to pay with. This SDK currently implements Tempo (charge and session intents).

## Protocol

Built on the ["Payment" HTTP Authentication Scheme](https://paymentauth.org), an open specification proposed to the IETF. See [mpp.dev/protocol](https://mpp.dev/protocol/) for the full protocol overview, or the [IETF specification](https://paymentauth.org) for the wire format.

## Contributing

```
git clone https://github.com/tempoxyz/mpp-rs
cd mpp-rs
cargo test
```

## Security

See [`SECURITY.md`](./SECURITY.md) for reporting vulnerabilities.

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or [MIT License](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in these crates by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
