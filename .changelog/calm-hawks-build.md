---
mpp: minor
---

Added zero-amount proof credential support for identity flows. Introduced a new `PayloadType::Proof` variant with EIP-712 signing via a new `proof` module, enabling clients to authenticate without sending a blockchain transaction. Updated `TempoCharge`, `TempoProvider`, and server-side verification to handle zero-amount challenges with signed proofs.
