---
mpp: patch
---

Added client and protocol helpers upstreamed from presto:
- `PaymentChallenge::is_expired()` and `expires_at()` for RFC 3339 challenge expiry checks
- `TempoNetwork` enum with `from_chain_id()`, `default_rpc_url()`, and `default_currency()` lookups
- `client::tempo::keychain` module with `query_key_spending_limit()` and `local_key_spending_limit()` for Tempo access key spending limit queries
