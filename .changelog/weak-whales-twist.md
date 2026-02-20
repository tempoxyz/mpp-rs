---
mpp: minor
---

Added `TempoCharge` builder API (`from_challenge() → sign() → into_credential()`), gas resolution (`resolve_gas()` and `resolve_gas_with_stuck_detection()` for mempool stuck-tx replacement), `SignOptions` for overriding nonce/gas/signing parameters, and `TempoClientError` with `classify_rpc_error()` for structured error classification. Moved `abi.rs` from `protocol::methods::tempo` to `client::tempo` and consolidated the `ITIP20` sol! definition.
