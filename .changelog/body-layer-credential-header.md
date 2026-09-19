---
mpp: patch
---

Fixed `PaymentBodyLayer` reading credentials from `Authorization` only. It now reads the header selected by the verifier, so servers created with `requires_auth` can verify body-bound payments sent in `Payment-Authorization`.
