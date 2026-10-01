---
mpp: patch
---

Fixed the axum extractors and tower payment layers discarding why a credential was rejected. A credential that fails because of a server-side fault (RPC, store, upstream API) is now answered with `500` and no fresh challenge instead of `402` with one, so auto-paying clients no longer pay twice. The axum extractors answer every rejected credential with an `application/problem+json` body carrying the problem type and challenge id, returned as the new `MppChargeRejection::Problem` instead of `VerificationFailed`/`VerificationFailedOffers`. A challenge that cannot be sent as a header value is answered with `500` instead of an id-less `WWW-Authenticate: Payment`, and `500` responses no longer contain internal error text.

Custom `ChargeChallenger` and `PaymentVerifier` implementations keep working and report every failure as `verification-failed`; implement the new `ChargeChallenger::verify_payment_for_route` and `PaymentVerifier::verify_credential` to report precise problems.
