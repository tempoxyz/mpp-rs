---
mpp: patch
---

Fixed the Stripe client not echoing a request-bound `externalId` in its credential, which made spec-compliant servers such as mppx reject the payment. The challenge's `externalId` now takes precedence over the one returned by `create_token`, and a challenge with a missing or empty `methodDetails.networkId` is rejected instead of passing an empty network ID to the callback.
