---
mpp: minor
---

Tagged failed sender and sponsored pre-broadcast simulations with a `PaymentSimulationError` (phase, sender, fee payer, payment token and the node's error) as the returned `VerificationError`'s new `source`, as mppx does; transport failures stay untagged.
