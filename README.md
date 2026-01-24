# mpay

Rust SDK for the Machine Payments Protocol (MPP) - an implementation of the ["Payment" HTTP Authentication Scheme](https://datatracker.ietf.org/doc/draft-ietf-httpauth-payment/).

## Design Principles

- **Protocol-first** — Core types (`Challenge`, `Credential`, `Receipt`) map directly to HTTP headers
- **Zero-copy parsing** — Efficient header parsing without unnecessary allocations
- **Pluggable methods** — Payment networks are feature-gated (Tempo included by default)
- **Minimal dependencies** — Core has minimal deps; features add what you need
- **Designed for extension** — `Method` and `Intent` are traits. Implement them for custom payment methods.

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
    request: serde_json::json!({"amount": "1000000", "asset": "0x...", "destination": "0x..."}),
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

## Install

```toml
[dependencies]
mpay = "0.1"
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `tempo` | Tempo blockchain support (default, includes `evm`) |
| `evm` | Shared EVM utilities (Address, U256, parsing) |
| `utils` | Encoding utilities (hex, base64) |

## What's NOT Included

Network registries, currency formatting, keystore management, HTTP clients, and middleware are out of scope for this library.

## Examples

See the [examples/](./examples/) directory for integration patterns with common HTTP libraries:

## Development

```bash
cargo build         # Build with default features (tempo)
cargo test          # Run tests
cargo doc --open    # Generate and view documentation
```

## License

MIT OR Apache-2.0
