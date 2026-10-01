---
mpp: patch
---

Fixed the Tempo fee payer co-signing sponsored transactions that spend its fee budget on work other than the charge. A sponsored transaction with an authorization list is now rejected, and an approve/swap prefix must approve exactly the swap's `maxAmountIn` and buy exactly the payment amount of the payment currency, matching mppx. Key authorizations stay sponsored by default; `ChargeMethod::with_fee_payer_allow_key_authorization(false)` rejects them.
