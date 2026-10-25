---
mpp: minor
---

Answer bare `402` challenges with an RFC 9457 `application/problem+json`
`payment-required` problem, as mppx does, instead of `{"error": "Payment Required"}`.
This applies to the axum `PaymentRequired` and `PaymentOffers` responses and to
`HttpTransport::respond_challenge`.
`ChallengeContext::error` is now `Option<&MppError>` (was `Option<&str>`):
`HttpTransport` sends the error's problem details with its status, and
`WsTransport` sends the problem's `detail`.
A `500` problem, sent without a challenge, carries no `challengeId`.
