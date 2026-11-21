---
mpp: patch
---

Bound a session open Credential's `source` to the payer its signed transaction authenticates (a direct payer signature, an access key the transaction authorizes for this chain, or an unrevoked, unexpired access key of the payer on chain), as mppx does. Credentials without a source are unchanged.
