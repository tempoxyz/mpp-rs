---
mpp: minor
---

With prepaid requests and a top-up amount configured, `TempoSessionProvider` tops a session channel up in the background once its deposit no longer covers the prepaid balance plus the next request, so the on-chain top-up does not hold up a later request.
