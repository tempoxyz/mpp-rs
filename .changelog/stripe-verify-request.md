---
mpp: patch
---

Fixed the Stripe `ChargeMethod::verify` ignoring its `request` argument. It created the PaymentIntent from the request echoed by the credential, so a caller that used the method directly, or `Mpp::verify`/`Mpp::broadcast` with its own request, charged whatever amount and currency the credential named. The PaymentIntent amount, currency, metadata and `externalId` binding now come from the request passed in, as in mppx. `Mpp::stripe_verify_charge` and the other credential entry points pass the echoed request after checking it and behave as before.
