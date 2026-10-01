---
mpp: minor
---

Fixed the Stripe server method ignoring `externalId`. A charge whose request carries an `externalId` now requires the credential payload to echo the same value and rejects it otherwise before creating the PaymentIntent, and the receipt carries the request's `externalId`. Clients must echo a request-bound `externalId`: mppx does, and `StripeProvider` does in releases after 0.14.0. PaymentIntent metadata values are now capped at Stripe's 500 characters, so a long client-supplied `source` can no longer make the request fail, and the method reuses one HTTP client instead of building one per verification.
