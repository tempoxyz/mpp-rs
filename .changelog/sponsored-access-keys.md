---
mpp: minor
---

Removed `TempoBuilder::fee_payer_allow_key_authorization` and `ChargeMethod::with_fee_payer_allow_key_authorization`: the fee payer now sponsors transactions that carry a key authorization, so an access key can pay in the transaction that installs it. The fee payer's gas and total-fee policy still bounds the cost.
