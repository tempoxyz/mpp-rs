---
mpp: patch
---

Reject zero-amount Tempo charge proofs when a payment challenge names a realm other than the requested host. Apply the check to HTTP payments, session bootstrap, MCP payments, and WebSocket clients. Respect a caller-supplied HTTP Host header, and allow a different server realm only when explicitly pinned to its HTTP origin with `with_trusted_tempo_proof_realm`.

Servers using the built-in `MPP Payment` realm or an auto-detected app name must configure a realm matching their public hostname, or clients must explicitly pin the server's realm to its HTTP origin before upgrading. Without that configuration, zero-amount Tempo proofs from those servers fail closed.
