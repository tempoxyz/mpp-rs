---
mpp: minor
---

Added client and protocol helpers upstreamed from presto: `PaymentChallenge::is_expired()` and `expires_at()` for RFC 3339 challenge expiry checks, `TempoNetwork` enum with chain ID and RPC URL lookups, and `client::tempo::keychain` module with `query_key_spending_limit()` and `local_key_spending_limit()` for Tempo access key spending limit queries. Also included minor test and async signature cleanup in server middleware and SSE modules.
