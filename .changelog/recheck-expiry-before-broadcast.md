---
mpp: patch
---

Re-check Tempo charge challenge expiry right before broadcasting a transaction credential (and before accepting a proof), and treat an `expires` equal to the current time as expired.
