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

[MPP](https://mpp.dev/) (the Machine Payments Protocol) is an open standard for machine-to-machine payments, co-authored by [Tempo](https://tempo.xyz/) and [Stripe](https://stripe.com/). Paying for a resource over HTTP typically requires API keys, billing accounts, or checkout flows set up ahead of time. MPP lets any client, including an AI agent, an app, or a person, pay as part of the HTTP exchange using the native [`402 Payment Required` response](https://mpp.dev/protocol/http-402).

This crate is the [Rust SDK](https://mpp.dev/sdk/rust) for MPP. It supports developers building either side of a paid HTTP exchange: servers that charge for access with Tempo or Stripe, and clients that automatically handle 402 payment challenges. Typical scenarios include gating an API behind per-call payments or building an agent that pays for tools or data as it works. See the [quickstart](https://mpp.dev/quickstart) for server and client patterns.

## MPP SDKs

MPP has official SDKs in multiple languages:

| Language | Repository |
|----------|------------|
| Rust | `mpp-rs` (this repository) |
| Go | [`tempoxyz/mpp-go`](https://github.com/tempoxyz/mpp-go) |
| Python | [`tempoxyz/pympp`](https://github.com/tempoxyz/pympp) |
| TypeScript | [`wevm/mppx`](https://github.com/wevm/mppx) |
| Ruby | [`stripe/mpp-rb`](https://github.com/stripe/mpp-rb) |

## Install

```bash
cargo add mpp
```

## Quick Start

### Server (Tempo)

```rust
use mpp::server::{Mpp, tempo, TempoConfig};

let mpp = Mpp::create(tempo(TempoConfig {
    recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
}))?;

let challenge = mpp.charge("1")?;
let receipt = mpp.verify_credential(&credential).await?;
```

### Server (Stripe)

```rust
use mpp::server::{Mpp, stripe, StripeConfig};

let mpp = Mpp::create_stripe(stripe(StripeConfig {
    secret_key: "sk_test_...",
    network_id: "internal",
    payment_method_types: &["card"],
    currency: "usd",
    decimals: 2,
}))?;

let challenge = mpp.stripe_charge("1")?;
let receipt = mpp.verify_credential(&credential).await?;
```

### Client (Tempo)

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

### Client (Stripe)

```rust
use mpp::client::{Fetch, StripeProvider};
use mpp::protocol::methods::stripe::CreateTokenResult;

let provider = StripeProvider::new(|params| {
    Box::pin(async move {
        // Proxy SPT creation through your backend (requires Stripe secret key)
        let resp = reqwest::Client::new()
            .post("https://my-server.com/api/create-spt")
            .json(&params)
            .send().await?.json::<serde_json::Value>().await?;
        Ok(CreateTokenResult::from(resp["spt"].as_str().unwrap().to_string()))
    })
});

let resp = reqwest::Client::new()
    .get("https://api.example.com/paid")
    .send_with_payment(&provider)
    .await?;
```

### WebSocket

```rust
use mpp::server::ws::{WsMessage, WsResponse};

// Server: parse incoming WS message, send challenge/receipt
let msg: WsMessage = serde_json::from_str(&text)?;
if let WsMessage::Credential { credential } = msg {
    let parsed = mpp::parse_authorization(&credential)?;
    let receipt = mpp.verify_credential(&parsed).await?;
    let resp = WsResponse::Receipt {
        receipt: serde_json::to_value(&receipt)?,
    };
    socket.send(resp.to_text()).await;
}

// Client: detect challenge, send credential
let msg: mpp::client::ws::WsServerMessage = serde_json::from_str(&text)?;
if let WsServerMessage::Challenge { challenge, .. } = msg {
    let cred_msg = serde_json::json!({
        "type": "credential",
        "credential": auth_string,
    });
    ws.send(cred_msg.to_string()).await;
}
```

WSS (WebSocket Secure) is handled at the connection layer. The transport itself is protocol-agnostic. On the server, terminate TLS via a reverse proxy (nginx, Cloudflare) or use `axum-server` with rustls. On the client, `tokio-tungstenite` supports `wss://` URLs via its `native-tls` or `rustls` features:

```toml
tokio-tungstenite = { version = "0.26", features = ["rustls-tls-webpki-roots"] }
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `client` | Client-side payment providers (`PaymentProvider` trait, `Fetch` extension) |
| `server` | Server-side payment verification (`ChargeMethod` trait) |
| `tempo` | [Tempo](https://tempo.xyz) blockchain support (includes `evm`) |
| `stripe` | [Stripe](https://stripe.com) payment support via SPTs |
| `evm` | Shared EVM utilities (Address, U256, parsing) |
| `middleware` | reqwest-middleware support with `PaymentMiddleware` (implies `client`) |
| `tower` | Tower middleware for server-side integration |
| `axum` | Axum extractor support for server-side convenience |
| `ws` | WebSocket transport for bidirectional session payments |
| `utils` | Hex/random utilities for development and testing |

## Payment Methods

MPP supports multiple [payment methods](https://mpp.dev/payment-methods) through one protocol: [Tempo](https://mpp.dev/payment-methods/tempo), [Stripe](https://mpp.dev/payment-methods/stripe), [Lightning](https://mpp.dev/payment-methods/lightning), [Card](https://mpp.dev/payment-methods/card), and [custom methods](https://mpp.dev/payment-methods/custom). The server advertises which methods it accepts, and the client chooses which one to pay with. This SDK implements Tempo (charge and session intents) and Stripe (charge intent via Shared Payment Tokens).

## Protocol

Built on the ["Payment" HTTP Authentication Scheme](https://paymentauth.org/). The source specifications are maintained in [`tempoxyz/mpp-specs`](https://github.com/tempoxyz/mpp-specs). See [mpp.dev/protocol](https://mpp.dev/protocol) for the protocol overview or [paymentauth.org](https://paymentauth.org/) for the wire format.

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
