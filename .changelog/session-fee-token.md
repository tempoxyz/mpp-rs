---
mpp: patch
---

Sessions pay gas for sponsored channel opens and top-ups in the `feeToken` the server advertises. Clients defaulted to the session currency, so a sponsored MACH channel named MACH as its gas token and the server rejected it.
