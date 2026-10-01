---
mpp: patch
---

Fixed the Stripe charge method reporting a PaymentIntent in `requires_action` (e.g. 3D Secure) as `verification-failed`. It now fails with the new `ErrorCode::PaymentActionRequired`, which is reported as the `payment-action-required` problem like in mppx.
