---
mpp: patch
---

Bounded each session management request (top-up, voucher and close) to 30 seconds, failing with an unknown payment outcome instead of holding the payment lock while a server stalls.
