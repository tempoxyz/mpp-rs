---
mpp: patch
---

Fixed `MultiProvider` rejecting challenges for providers that send no `Accept-Payment` header, such as a Stripe-only offer failing with `NoSupportedChallenge` next to a Tempo session provider. `TempoProvider`, `TempoSessionProvider`, `TempoAccountsProvider` and `StripeProvider` now advertise the methods they support, and `MultiProvider` merges its children's headers, sending none if a child does not advertise.
