---
mpp: minor
---

Added Stripe payment method support (`method="stripe"`, `intent="charge"`) with client-side `StripeProvider` for SPT creation, server-side `ChargeMethod` for PaymentIntent verification, and `Mpp::create_stripe()` builder integration. Added `stripe` and `integration-stripe` feature flags backed by `reqwest`.
