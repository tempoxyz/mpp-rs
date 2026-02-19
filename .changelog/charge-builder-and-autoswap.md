---
mpp: minor
---

Added Stripe-like `TempoCharge` builder API, auto-swap routing, and stuck-transaction detection:

- `TempoCharge::from_challenge()` → `sign()` → `into_credential()` for simple 3-line payment flows
- `SignOptions` for power users to override nonce, gas, signing mode, fee token, and RPC URL
- `TempoProvider` now handles auto-swap routing: detects insufficient balance, finds an alternative token with enough balance and spending limit, and builds swap calls automatically
- `resolve_gas_with_stuck_detection()` compares confirmed vs pending nonce to detect and replace stuck mempool transactions with aggressive gas bumping
- `replace_stuck_txs` flag on both `SignOptions` and `TempoProvider`
- `routing::find_swap_source()` and `select_swap_source()` with keychain-aware spending limit filtering
- `balance::query_token_balance()` and `effective_capacity()` for balance + spending limit checks
- `swap::build_swap_calls()` and `build_open_calls()` for DEX swap and escrow flows
- `format_u256_with_decimals()` and `format_u256_trimmed()` utilities in `evm` module
- `known_tokens()` on `TempoNetwork` for token registry lookups
- Moved `abi.rs` from `protocol::methods::tempo` to `client::tempo` (execution-level code, not protocol data types)
- Consolidated `ITIP20` sol! definition into `abi.rs`
