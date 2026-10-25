---
mpp: patch
---

The default `ChargeChallenger::verify_payment_for_amount_and_scope` and `verify_payment_for_amount_scope_and_body` now verify framework route binding, as mppx does: instead of rejecting every scoped request, they re-issue the route's challenge with `challenge` (or `challenge_with_body`) and accept a credential only when its echoed challenge carries the route's `_mppx_scope` and the same method, intent, body digest and pinned request fields (amount, currency, recipient and method details, as in mppx), so a `description` the re-issued challenge lacks does not reject it, so a credential issued for another route, amount, HTTP method or body is rejected. Custom challengers that bind `ChallengeOptions::mppx_scope` into a deterministic challenge request now work with the Axum extractors without overriding these methods; their `verify_payment` must still authenticate the echoed challenge.
