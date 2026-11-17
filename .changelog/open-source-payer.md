---
mpp: patch
---

Bound a session open credential's `source` to the payer its signed transaction authenticates: a direct payer signature, an access key the transaction authorizes for this chain, or an unrevoked, unexpired access key of the payer on chain. Credentials without a source are unchanged.
