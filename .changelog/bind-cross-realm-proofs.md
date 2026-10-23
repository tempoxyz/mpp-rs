---
mpp: patch
---

Reject zero-amount Tempo charge proofs when a payment challenge names a realm other than the requested host. Apply the same check when bootstrapping sessions so a relayed challenge cannot obtain a proof for another server.
