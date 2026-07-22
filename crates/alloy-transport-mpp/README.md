# alloy-transport-mpp

[Machine Payments Protocol (MPP)](https://github.com/tempoxyz/mpp-rs)
WebSocket transport for [alloy](https://github.com/alloy-rs/alloy).

This crate adds opt-in WebSocket transports that speak the MPP wire protocol.
`MppWsConnect` is a drop-in Alloy `PubSubConnect` implementation for JSON-RPC,
while `MppApplicationWsConnect` carries arbitrary text application messages.
Both wrap payloads in canonical MPP `message` envelopes and handle payment
`challenge`, `needVoucher`, `receipt`, signed session close, and `error` frames
internally via a user-supplied
[`PaymentProvider`](https://docs.rs/mpp/latest/mpp/client/trait.PaymentProvider.html)
(and a `VoucherProvider` for streaming/session intents).

Ring is the default TLS backend. Select another backend explicitly and disable
default features so Cargo does not compile more than one crypto provider:

```toml
alloy-transport-mpp = { git = "https://github.com/tempoxyz/mpp-rs", default-features = false, features = ["aws-lc-rs"] }
```

The available backend features are `ring`, `aws-lc-rs`, and `native-tls`.
`rustls-tls` exposes the provider-neutral Rustls plumbing for applications that
install their own process-wide Rustls crypto provider.

```rust,ignore
use alloy_provider::ProviderBuilder;
use alloy_transport_mpp::MppWsConnect;

let connect = MppWsConnect::new("wss://paid.example/rpc", my_provider);
let provider = ProviderBuilder::new().connect_pubsub(connect).await?;
```

For non-JSON-RPC protocols, such as the OpenAI Responses WebSocket API, use
the application transport directly:

```rust,ignore
use alloy_transport_mpp::MppApplicationWsConnect;

let connect = MppApplicationWsConnect::new(
    "wss://paid.example/v1/responses",
    payment_provider,
    voucher_provider,
);
let mut socket = connect.connect().await?;

socket.send(r#"{"type":"response.create","model":"gpt-5.6-sol"}"#).await?;
while let Ok(message) = socket.next().await {
    // Handle application messages. Payment frames stay inside the transport.
}

// Performs the canonical close-request/close-ready/signed-close handshake.
let final_receipt = socket.close().await?;
```
