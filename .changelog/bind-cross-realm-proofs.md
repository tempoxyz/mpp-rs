---
mpp: patch
---

Reject zero-amount Tempo charge proofs when a payment challenge names a realm other than the requested host. Apply the check to HTTP payments, session bootstrap, MCP payments, and WebSocket clients. Respect a caller-supplied HTTP Host header when checking the requested host.
