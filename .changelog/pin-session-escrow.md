---
mpp: patch
---

Fixed the Tempo session client trusting any escrow contract advertised by the server, which let a malicious server have the client approve and deposit into a contract of its choosing. Only the canonical escrow for the chain (or the one set with `with_escrow_contract`) is accepted now, and a challenge's `sessionProtocol` must match the escrow it is answered on. Use `TempoSessionProvider::with_allow_custom_escrow(true)` to accept server-chosen escrows, e.g. for local deployments.
