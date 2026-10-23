---
mpp: patch
---

Reject zero-amount Tempo charge proofs when a payment challenge names a realm other than the requested host. Apply the check to HTTP payments, session bootstrap, MCP payments, and WebSocket clients. Respect a caller-supplied HTTP Host header, and allow a different server realm only when explicitly pinned to its HTTP origin with `with_trusted_tempo_proof_realm`.

The Axum extractors now use the HTTP request hostname as the default challenge realm and verify against the same realm, matching mppx. An explicit `.realm(...)` or `MPP_REALM` still takes precedence. Servers issuing challenges outside an HTTP request (such as direct `Mpp::charge` calls or WebSocket handlers) continue to use their configured or environment-detected realm; those servers must configure a realm matching their public hostname or clients must pin the realm to its HTTP origin. Without that configuration, zero-amount Tempo proofs fail closed.
