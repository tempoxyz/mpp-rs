---
mpp: patch
---

Standardized Stripe PaymentIntent analytics metadata to match mppx: every PaymentIntent records `machine_payment`, the SDK identifier `mpp_sdk` (`mpp-rs/<version>`), `mpp_challenge_id` and `mpp_intent`, and no longer records `mpp_server_id` or `mpp_client_id`. Challenge `methodDetails.metadata` is applied after these keys.
