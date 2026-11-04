---
mpp: patch
---

Added `with_http_client` to `TempoProvider`, `TempoSessionProvider`, `TempoAccountsProvider` and `TempoCharge`, which sends every Tempo RPC request through a caller-supplied `reqwest::Client`, for example one setting a Tempo Console API key in the `tempo-api-key` header, as mppx's `getClient` does.
