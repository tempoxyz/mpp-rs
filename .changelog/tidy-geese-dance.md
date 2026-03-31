---
mpp: patch
---

Added split payments support to Tempo charge verification and transaction building. Extended `TempoCharge` and `TempoChargeExt` to parse and propagate split recipients from `methodDetails`, and refactored transfer call construction and verification to handle multiple transfers using order-insensitive matching.
