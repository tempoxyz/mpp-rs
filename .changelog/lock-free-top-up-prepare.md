---
mpp: patch
---

Background session top-ups read chain state and sign without holding the payment lock, which they now take only to record the new deposit.
