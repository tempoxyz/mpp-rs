# mpp-rs

**Micropayments Protocol for Rust** - A library for implementing the Web Payment Auth protocol (IETF draft-ietf-httpauth-payment).

This is the Rust equivalent of [mpay](https://github.com/tempoxyz/mpay) (TypeScript).

## Installation

```toml
[dependencies]
mpp-rs = { git = "https://github.com/tempoxyz/mpp-rs" }
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `evm` | EVM blockchain support (default) |
| `tempo` | Tempo blockchain support (includes `evm`) |
| `keystore` | Keystore format encryption/decryption |
| `utils` | Encoding utilities (bs58, hex, base64) |
| `client` | High-level HTTP client |
| `http-client` | Low-level HTTP client support |
| `tower-middleware` | Tower middleware for servers |
| `reqwest-middleware` | Reqwest middleware for clients |

## Usage

### Parsing a Payment Challenge

```rust
use mpp_rs::{Challenge, Intent};

let header = r#"Payment method="tempo" intent="charge" request="eyJhbW91bnQiOiIxMDAwMDAwIn0""#;
let challenge = Challenge::parse_www_authenticate(header)?;

// Decode the charge request
let charge: Intent::ChargeRequest = challenge.request.decode()?;
println!("Amount: {}", charge.amount);
```

### Creating a Payment Credential

```rust
use mpp_rs::{Credential, PrivateKeySigner, Signer};

// Use your own signer (mpp-rs re-exports alloy's Signer trait)
let signer: PrivateKeySigner = "0x...".parse()?;

let credential = Credential::PaymentCredential::with_source(
    challenge.to_echo(),
    &format!("did:pkh:eip155:{}:{:#x}", chain_id, signer.address()),
    Credential::PaymentPayload::transaction("0x...signed_tx"),
);

let auth_header = Credential::format_authorization(&credential)?;
```

### Keystore Operations

```rust
use mpp_rs::keystore::{encrypt_keystore, decrypt_keystore};

// Encrypt a private key (mpp-rs only handles the format, not paths)
let json = encrypt_keystore(&private_key_bytes, "password")?;

// Decrypt later
let key_bytes = decrypt_keystore(&json, "password")?;
```

## Design Principles

1. **Batteries Included**: Re-exports `Signer` trait and `PrivateKeySigner` from alloy
2. **No Path Management**: Keystore module only handles format, not file paths
3. **Consumer Owns Signing**: Accepts `impl Signer` or `Arc<dyn Signer>` - you provide the signer
4. **mpay-style Exports**: Namespaced modules like `Challenge`, `Credential`, `Receipt`, `Intent`

## Separation from purl

mpp-rs is the protocol library. purl is the CLI that uses mpp-rs and owns:
- Keystore management (paths, listing, caching)
- Config file loading (TOML, platform paths)
- Password prompting
- CLI commands

## License

MIT OR Apache-2.0
