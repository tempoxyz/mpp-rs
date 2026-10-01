---
mpp: patch
---

Fixed `TempoSessionProvider::pay` waiting forever when an earlier payment was never committed, rolled back or abandoned, as in the documented example. The wait for the payment lock now ends when the challenge expires and fails with `PaymentExpired`, and the example shows how to settle a credential before paying again.
