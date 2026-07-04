---
mpp: major
---

Payment challenge/re-challenge `402` responses now carry an RFC 9457
`application/problem+json` body whose `type` reflects the specific failure
(`malformed-credential`, `verification-failed`, `payment-expired`, etc.), per
draft-httpauth-payment-00 §5.3.1. Bare challenges use a `payment-required`
problem.

Breaking changes for custom server integrations:

- `ChallengeContext.error` is now `Option<&MppError>` (was `Option<&str>`), so
  `Transport` implementations carry the typed error to the response layer.
- `PaymentRequired` is now a struct `{ challenge, error: Option<MppError> }` with
  `PaymentRequired::new(challenge)` and `PaymentRequired::with_error(challenge, error)`
  constructors (was a `PaymentRequired(PaymentChallenge)` tuple).
- `ChargeChallenger::{challenge, verify_payment, verify_payment_for_amount}` now
  return `MppError` instead of `String`.

Wire change: the HTTP transport and axum extractor previously returned
`application/json` `{"error": ...}` bodies on `402`; they now return
`application/problem+json` RFC 9457 documents. The Tower middleware is
unaffected (its generic response body cannot carry a JSON document).
