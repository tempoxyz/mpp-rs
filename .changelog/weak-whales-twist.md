---
mpp: minor
---

Added `TempoCharge` builder API, auto-swap routing, and stuck-transaction detection. Introduced `SignOptions` for overriding nonce/gas/signing parameters, `balance::query_token_balance()` and `effective_capacity()` for pre-flight balance checks, `routing::find_swap_source()` for keychain-aware swap candidate selection, `gas::resolve_gas_with_stuck_detection()` for mempool stuck-tx replacement, `build_swap_calls()` and `build_open_calls()` in the swap module, `format_u256_with_decimals()` and `format_u256_trimmed()` utilities, and `known_tokens()` on `TempoNetwork`. Moved `abi.rs` from `protocol::methods::tempo` to `client::tempo` and consolidated the `ITIP20` sol! definition.
