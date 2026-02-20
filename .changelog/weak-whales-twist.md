---
mpp: minor
---

Added `TempoCharge` builder API, gas resolution, and stuck-transaction detection. Introduced `SignOptions` for overriding nonce/gas/signing parameters, `balance::query_token_balance()` for pre-flight balance checks, `gas::resolve_gas_with_stuck_detection()` for mempool stuck-tx replacement, `format_u256_with_decimals()` and `format_u256_trimmed()` utilities, and `known_tokens()` on `TempoNetwork`. Moved `abi.rs` from `protocol::methods::tempo` to `client::tempo` and consolidated the `ITIP20` sol! definition.
