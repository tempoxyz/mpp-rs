---
mpp: patch
---

`compose_verify_with_expected_requests` now dispatches a credential to the route whose handler issued its challenge for that route's expected request when several routes share a payment method, such as two Tempo handlers with different currencies, recipients or scopes, instead of checking it against the first handler for that method. Added `ChargeVerifier::issued_credential_for`, which `Mpp` implements with its challenge HMAC and expected-request checks (including every currency it offers).
