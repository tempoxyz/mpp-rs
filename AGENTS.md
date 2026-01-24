# AGENTS.md

## Repository Overview

This is **mpp-rs** (Micropayments Protocol - Rust) - a library for implementing the Web Payment Auth protocol (IETF draft-ietf-httpauth-payment).

This is the Rust equivalent of [mpay](https://github.com/tempoxyz/mpay) (TypeScript).

## Commands

```bash
cargo build                    # Build with default features (evm)
cargo build --features tempo   # Build with Tempo support
cargo build --features keystore # Build with keystore support
cargo test                     # Run tests
cargo test --features "evm,keystore"  # Run tests with all features
cargo doc --open               # Generate and view documentation
```

## Architecture

### What mpp-rs Owns

- **Protocol types**: `PaymentChallenge`, `PaymentCredential`, `PaymentReceipt`
- **Payment methods**: `tempo`, `evm`, `stripe` adapters
- **Payment intents**: `ChargeRequest`, `AuthorizeRequest`, `SubscriptionRequest`
- **Network/currency registries**: Built-in network definitions
- **Money formatting**: Type-safe token amounts with `Money` and `TokenId`
- **Keystore format**: Encrypt/decrypt functions only (NO paths, NO discovery)
- **Crypto helpers**: Key generation and validation

### What mpp-rs Does NOT Own (purl's responsibility)

- Keystore management (list_keystores, default_keystore_dir, password cache)
- Config file loading (TOML paths, platform-specific paths)
- Password prompting (rpassword, dialoguer)
- CLI commands (clap)

### Signer Pattern

mpp-rs re-exports alloy's `Signer` trait. Consumers provide their own signer:

```rust
use mpp_rs::{Signer, PrivateKeySigner};

// Load your signer however you want
let signer: PrivateKeySigner = "0x...".parse()?;

// Use it with mpp-rs
let credential = create_credential(challenge, &signer).await?;
```

## Module Structure

```
src/
├── lib.rs           # Re-exports, mpay-style namespace modules
├── error.rs         # MppError, Result type
├── protocol/
│   ├── core/        # PaymentChallenge, Credential, Receipt, headers
│   ├── intents/     # ChargeRequest, AuthorizeRequest, SubscriptionRequest
│   └── methods/     # tempo/, evm/, stripe/ adapters
├── network.rs       # Network registry (built-in only, no config loading)
├── currency.rs      # Currency definitions
├── money.rs         # TokenId, Money (feature = "evm")
├── crypto.rs        # Key generation (feature = "evm")
├── keystore.rs      # Encrypt/decrypt only (feature = "keystore")
└── utils.rs         # Hex/address utilities
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `evm` | EVM support, enables Signer re-exports (default) |
| `tempo` | Tempo blockchain support (includes `evm`) |
| `keystore` | Keystore format encrypt/decrypt |
| `utils` | Encoding utilities |
| `stripe` | Stripe payment method |

## Code Style

- Follow existing patterns in purl/lib
- Use `MppError` for all error types
- Feature gate heavy dependencies (alloy, tempo-primitives)
- Doc examples should use `mpp_rs::` not `purl::`

## Dependencies

Based on purl/lib but without purl-specific features:
- `alloy` / `alloy-signer-local` for EVM
- `eth-keystore` for keystore format
- `tempo-primitives` for Tempo support
- `serde` / `serde_json` / `thiserror` for core types
