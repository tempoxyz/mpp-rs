---
mpp: patch
---

Added client-side payment event hooks (`ClientEvents`, `ClientEventSubscription`) with typed callbacks for `challenge.received`, `credential.created`, `payment.response`, and `payment.failed` events. Added `send_with_payment_options` to `PaymentExt` for passing event observers into the 402 payment flow, and pinned `alloy-sol-type-parser`, `alloy-sol-types`, and `tempo-contracts` dependencies to exact versions.
