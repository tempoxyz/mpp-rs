---
"alloy-transport-mpp": minor
---

Add an Alloy HTTP JSON-RPC transport that delegates automatic 402 challenge,
payment retry, and commit/rollback handling to the canonical MPP client flow,
with an optional concurrency bound for high-fanout consumers. Preserve
whitelisted HTTP diagnostics on unsuccessful JSON-RPC responses.
