---
mpp: minor
---

`PaymentResponseContext` now carries the paid request's `url` and the response's boxed `receipt`, so `payment.response` handlers can show who was paid and the settlement reference (a charge's transaction or a session's channel) without parsing headers. A session receipt is included only when it matches the challenge and the paying channel, as before.
