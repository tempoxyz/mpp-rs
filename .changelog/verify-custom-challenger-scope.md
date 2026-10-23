---
mpp: patch
---

The default `ChargeChallenger::verify_payment_for_amount_and_scope` and `verify_payment_for_amount_scope_and_body` now verify framework route scope, as mppx does: they accept a credential whose echoed challenge request carries the route's `_mppx_scope` and reject one bound to another route, instead of rejecting every scoped request. Custom challengers that bind `ChallengeOptions::mppx_scope` into the challenge request now work with the Axum extractors without overriding these methods; their `verify_payment` must still authenticate the echoed challenge.
