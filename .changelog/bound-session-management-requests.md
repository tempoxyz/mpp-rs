---
mpp: patch
---

Bounded each session management request (top-up, voucher and close), including reading an error response's body, to 30 seconds, failing with an unknown payment outcome instead of holding the payment lock while a server stalls. A top-up whose outcome is unknown, including one whose management transport fails with `MppError::Http`, blocks further top-ups on that channel until it is reconciled, so a late-applied deposit is not signed again.
