# Changelog

## 0.9.1 (2026-04-07)

### Patch Changes

- Enforced fail-closed behavior for the `expires` field in `verify_hmac_and_expiry`. Credentials missing the `expires` field are now rejected with a `CredentialMismatch` error instead of being silently accepted. Session challenges now include a default expiry. (by @EvanChipman, [#194](https://github.com/tempoxyz/mpp-rs/pull/194))
- Fixed busy loop in `serve()` caused by default `wait_for_update()` returning immediately instead of pending. (by @EvanChipman, [#194](https://github.com/tempoxyz/mpp-rs/pull/194))

## 0.9.0 (2026-04-07)

### Minor Changes

- Added zero-amount proof credential support for identity flows. Introduced a new `PayloadType::Proof` variant with EIP-712 signing via a new `proof` module, enabling clients to authenticate without sending a blockchain transaction. Updated `TempoCharge`, `TempoProvider`, and server-side verification to handle zero-amount challenges with signed proofs. (by @BrendanRyan, [#182](https://github.com/tempoxyz/mpp-rs/pull/182))

## 0.8.4 (2026-04-02)

### Patch Changes

- Bind payee and currency validation to all session actions (open, voucher, close, topUp). (by @horsefacts, [#188](https://github.com/tempoxyz/mpp-rs/pull/188))

## 0.8.3 (2026-03-31)

### Minor Changes

- Client now matches challenges by `provider.supports(method, intent)` instead of assuming a single challenge, mirroring the mppx TypeScript SDK. Both `PaymentExt` (fetch) and `PaymentMiddleware` parse all challenges and select the first one the provider supports. (by @grandizzy, [#185](https://github.com/tempoxyz/mpp-rs/pull/185))
- Added `HttpError::NoSupportedChallenge` variant for when a 402 response contains no challenge matching the provider's supported methods. (by @grandizzy, [#185](https://github.com/tempoxyz/mpp-rs/pull/185))

### Patch Changes

- Added split payments support to Tempo charge verification and transaction building. Extended `TempoCharge` and `TempoChargeExt` to parse and propagate split recipients from `methodDetails`, and refactored transfer call construction and verification to handle multiple transfers using order-insensitive matching. (by @BrendanRyan, [#187](https://github.com/tempoxyz/mpp-rs/pull/187))

## 0.8.2 (2026-03-31)

### Patch Changes

- Fixed a timing side-channel in HMAC challenge ID verification by replacing non-constant-time string comparison with `constant_time_eq`. Added an `ast-grep` lint rule to prevent future regressions. (by @BrendanRyan, [#175](https://github.com/tempoxyz/mpp-rs/pull/175))

## 0.8.1 (2026-03-30)

### Patch Changes

- Fixed a race condition in `ChannelStoreAdapter` where concurrent `update_channel` calls for the same channel could overwrite each other. Added per-channel async mutex locking to serialize read-modify-write operations within a single process, along with tests reproducing the original race. (by @BrendanRyan, [#177](https://github.com/tempoxyz/mpp-rs/pull/177))

## 0.8.0 (2026-03-26)

### Minor Changes

- Added a Stripe Shared Payment Token (SPT) example demonstrating the full 402 → challenge → credential → retry flow using Stripe's payment method. Includes a server with SPT proxy endpoint and a headless client using a test card. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Added `fee_payer()` and `chain_id()` getters to `Mpp`. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Added Stripe payment method support (`method="stripe"`, `intent="charge"`) with client-side `StripeProvider` for SPT creation, server-side `ChargeMethod` for PaymentIntent verification, and `Mpp::create_stripe()` builder integration. Added `stripe` and `integration-stripe` feature flags backed by `reqwest`. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))

### Patch Changes

- Fixed multiple payment bypass and griefing vulnerabilities (GHSA-fxc9-7j2w-vx54). (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Bumped `alloy` dependency from 1.7 to 1.8 and `tempo-alloy`/`tempo-primitives` from 1 to 1.5 across the main crate and all examples. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Disabled tempo lint PR comments while keeping the lint CI check enforced. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))
- Fixed `base64url_decode` to accept standard base64 (`+`, `/`, `=` padding) in addition to URL-safe base64, following Postel's law and aligning with the mppx TypeScript SDK behavior. Added tests covering standard base64 with padding, URL-safe without padding, and standard alphabet without padding in both `types.rs` and `headers.rs`. (by @BrendanRyan, [#172](https://github.com/tempoxyz/mpp-rs/pull/172))

## 0.7.0 (2026-03-23)

### Minor Changes

- Refactored Tempo client to use `tempo_alloy` types instead of local duplicates. Removed the local `abi.rs` module and replaced local ABI definitions (`ITIP20`, `IStablecoinDEX`, `IAccountKeychain`) with imports from `tempo_alloy::contracts::precompiles`. Simplified gas estimation to use the provider's `estimate_gas` method via `TempoTransactionRequest` instead of manual JSON-RPC construction. (by @BrendanRyan, [#143](https://github.com/tempoxyz/mpp-rs/pull/143))

## 0.6.0 (2026-03-22)

### Minor Changes

- Migrated tempo dependencies (`tempo-alloy`, `tempo-primitives`) from git dependencies to crates.io versioned dependencies, and added `cargo publish` to the release workflow with registry token support. (by @BrendanRyan, [#142](https://github.com/tempoxyz/mpp-rs/pull/142))

### Patch Changes

- Fixed core problem type base URI to use the canonical `https://paymentauth.org/problems` domain instead of the temporary GitHub Pages URL. (by @BrendanRyan, [#142](https://github.com/tempoxyz/mpp-rs/pull/142))

## `mpp@0.5.0`

### Minor Changes

- Added fee payer support to the Tempo payment provider. The client now builds 0x76 transactions with expiring nonces and a placeholder fee payer signature, and the server co-signs them by recovering the sender, setting the fee token, and re-encoding as a standard 0x76 transaction with both signatures. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added comprehensive integration and unit test coverage across client fetch, client middleware, MCP payment roundtrip, server middleware, server HMAC challenge verification, and SSE metered streaming flows. Also added a `feature-matrix` CI job to validate all feature flag combinations, and introduced `Mpp::new_with_config` test helper and made `detect_realm` pub(crate). (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added network-specific default currencies for Tempo, defaulting to USDC (USDC.e) on mainnet and pathUSD on testnet. Deprecated the `DEFAULT_CURRENCY` constant in favor of `DEFAULT_CURRENCY_MAINNET` and `DEFAULT_CURRENCY_TESTNET`. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added `TempoCharge` builder API (`from_challenge() → sign() → into_credential()`), gas resolution (`resolve_gas()` and `resolve_gas_with_stuck_detection()` for mempool stuck-tx replacement), `SignOptions` for overriding nonce/gas/signing parameters, and `TempoClientError` with `classify_rpc_error()` for structured error classification. Moved `abi.rs` from `protocol::methods::tempo` to `client::tempo` and consolidated the `ITIP20` sol! definition. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added end-to-end support for the `0x78` fee payer envelope format, enabling clients to request gas sponsorship by sending a `0x78 || RLP(...)` encoded transaction that servers co-sign and broadcast as a standard `0x76` Tempo transaction. Extended server-side verification to accept both `0x76` and `0x78` transaction types, added `sign_and_encode_fee_payer_envelope` signing helpers, and added integration tests asserting on-chain fee payer and sender addresses. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added integration tests for the MPP charge flow against a live Tempo blockchain. Introduced an `integration` feature flag, updated dev dependencies (`axum`, `reqwest`, `hex`, tokio `net` feature), added a `test-integration` Makefile target, and added `tests/integration_charge.rs` with E2E tests covering health checks, 402 challenge flow, full charge round-trips, and auth scheme validation. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))

### Patch Changes

- Added comprehensive test coverage for session provider, channel store, and session verification logic. Tests cover voucher sending edge cases, channel state management, HMAC validation, and `SessionVerifyResult` debug formatting. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Auto-detect `realm` from environment variables in `Mpp::create()`. Checks `MPP_REALM`, `FLY_APP_NAME`, `HEROKU_APP_NAME`, `HOST`, `HOSTNAME`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`, `VERCEL_URL`, `WEBSITE_HOSTNAME` in order, falling back to `"MPP Payment"`. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Updated URLs from `machinepayments.dev` to `mpp.dev` in README and removed "web3" keyword from Cargo.toml metadata. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added auto-detection of `realm` from environment variables in `Mpp::create()`. Checks `MPP_REALM`, `FLY_APP_NAME`, `HEROKU_APP_NAME`, `HOST`, `HOSTNAME`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`, `VERCEL_URL`, and `WEBSITE_HOSTNAME` in order, falling back to `"MPP Payment"`. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Introduced `TempoClientError` enum scoped under `client::tempo` for typed Tempo-specific client errors (AccessKeyNotProvisioned, SpendingLimitExceeded, InsufficientBalance, TransactionReverted). Added `MppError::Tempo` variant gated on `client + tempo` features with `classify_rpc_error` to parse RPC error messages into typed variants, replacing brittle string matching in downstream consumers. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added `TempoSigningMode` enum (Direct/Keychain) and centralized transaction helpers for client-side Tempo payments. New `client::signing` module provides `sign_and_encode` / `sign_and_encode_async` with keychain envelope support. New `client::tx_builder` module provides `TempoTxOptions`, `build_tempo_tx`, `estimate_gas`, `build_estimate_gas_request`, and `build_charge_credential`. Updated `TempoProvider`, `TempoSessionProvider`, and `create_open_payload` to use the new signing mode abstraction, eliminating duplicated transaction construction logic across consumers. Fixed potential `u64` overflow in `parse_gas_estimate` by using `checked_add`. Added 46 new unit tests (432 → 478) covering signature variant correctness, encoding boundary conditions, escrow resolution priority, deposit edge cases, re-export verification, and gas estimate overflow protection. (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))
- Added client and protocol helpers upstreamed from presto:
- `PaymentChallenge::is_expired()` and `expires_at()` for RFC 3339 challenge expiry checks
- `TempoNetwork` enum with `from_chain_id()`, `default_rpc_url()`, and `default_currency()` lookups
- `client::tempo::keychain` module with `query_key_spending_limit()` and `local_key_spending_limit()` for Tempo access key spending limit queries
- ABI encoding helpers (`encode_transfer`, `encode_approve`, `encode_swap_exact_amount_out`, `DEX_ADDRESS`) in `protocol::methods::tempo::abi`
- `PaymentChallenge::validate_for_charge()` and `validate_for_session()` for common challenge validation
- `network()` convenience methods on `TempoChargeExt` and `TempoSessionExt`
- `parse_memo_bytes()` utility for hex memo string to 32-byte array conversion
- `extract_tx_hash()` utility for extracting transaction hashes from base64url receipts (by @BrendanRyan, [#89](https://github.com/tempoxyz/mpp-rs/pull/89))

## `mpp@0.4.0`

### Minor Changes

- Added Axum middleware support with extractors and response types, updated library description to "402 Protocol", and made SSE stream pluggable by returning a `Stream` instead of `Receiver`. (by @BrendanRyan, [#59](https://github.com/tempoxyz/mpp-rs/pull/59))

### Patch Changes

- Fixed parameter parsing to reject duplicate parameters, empty challenge IDs, and non-ISO8601 timestamp formats in conformance with protocol strictness requirements. (by @BrendanRyan, [#59](https://github.com/tempoxyz/mpp-rs/pull/59))

## `mpp@0.3.0`

### Minor Changes

- Simplified server API with dollar amounts and smart defaults. Added `Mpp::create()` and `mpp.charge("1")` for one-line payment setup.
- Added default 5-minute expiration for challenges and `prepare_request` hook for request customization.
- Aligned Rust SDK with mppx TypeScript SDK for cross-language consistency.
- Removed failed receipt state — server now returns 402 for payment failures per IETF spec.
- Fixed tempo payment method to match TypeScript SDK behavior. Fixed 402 responses for failed receipts per spec.
- Updated `rand` dependency from 0.8 to 0.9. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))

### Patch Changes

- Mandated JCS (RFC 8785) for canonical JSON serialization of request parameters by replacing `serde_json::to_string` with `serde_json_canonicalizer::to_string` throughout the protocol layer. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Updated currency address from AlphaUSD to PathUSD across all examples, documentation, and tests. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Normalized error codes to kebab-case format per IETF spec update (§8.2). (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))
- Updated documentation URL and optimized CI workflows. Added GitHub Pages documentation deployment, switched to cargo-hack for feature testing, and pinned release workflow to commit SHA. (by @BrendanRyan, [#56](https://github.com/tempoxyz/mpp-rs/pull/56))

