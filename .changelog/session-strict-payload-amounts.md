---
mpp: patch
---

Fixed the Tempo session method accepting a leading `+` in the `cumulativeAmount` and `additionalDeposit` of session credentials. These amounts must be ASCII digits only, like the challenge amounts.
