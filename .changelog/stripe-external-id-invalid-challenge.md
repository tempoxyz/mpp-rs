---
mpp: patch
---

A Stripe charge credential whose `externalId` does not match the request-bound `externalId` (or omits it) is now rejected with the `invalid-challenge` problem (402), matching mppx's `InvalidChallengeError`, instead of `verification-failed`. It is still rejected before any PaymentIntent is created.
