---
mpp: patch
---

Verified session `close` and `voucher` signatures before comparing the voucher against the channel, so unauthenticated requests no longer learn a channel's spent or accepted amount from the error.
