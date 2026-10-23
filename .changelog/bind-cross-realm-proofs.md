---
mpp: patch
---

Reject zero-amount Tempo charge proofs when a payment challenge names a realm other than the requested host. Apply the check to HTTP payments, session bootstrap, MCP payments, and WebSocket clients. Respect a caller-supplied HTTP Host header, and allow a different server realm only when explicitly pinned to its HTTP origin with `with_trusted_tempo_proof_realm`.
