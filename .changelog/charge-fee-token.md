---
mpp: patch
---

Added `TempoProvider::with_fee_token`, so an access key whose spending limits exclude the default fee token can pay an unsponsored charge's fee in a token it may spend, as mppx's `feeToken` on the Tempo charge client does.
