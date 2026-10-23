---
mpp: patch
---

Sponsored charge transactions that install an access key are now rejected unless the server opts in with `TempoBuilder::fee_payer_allow_key_authorization(true)` (or `ChargeMethod::with_fee_payer_allow_key_authorization(true)`), matching mppx. Previously the fee payer sponsored key authorizations by default.
