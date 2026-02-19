---
mpp: patch
---

Introduced `TempoClientError` enum scoped under `client::tempo` for typed Tempo-specific client errors (AccessKeyNotProvisioned, SpendingLimitExceeded, InsufficientBalance, TransactionReverted). Added `MppError::Tempo` variant gated on `client + tempo` features with `classify_rpc_error` to parse RPC error messages into typed variants, replacing brittle string matching in downstream consumers.
