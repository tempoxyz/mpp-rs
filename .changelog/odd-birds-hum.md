---
mpp: minor
---

Refactored Tempo client to use `tempo_alloy` types instead of local duplicates. Removed the local `abi.rs` module and replaced local ABI definitions (`ITIP20`, `IStablecoinDEX`, `IAccountKeychain`) with imports from `tempo_alloy::contracts::precompiles`. Simplified gas estimation to use the provider's `estimate_gas` method via `TempoTransactionRequest` instead of manual JSON-RPC construction.
