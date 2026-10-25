---
mpp: patch
---

When a paid retry, or a request sent with a prepaid credential, returns a 5xx response or fails to send, the client now emits `payment.failed` with `PaymentFailureReason::OutcomeUnknown`, carrying the status, the serialized credential and, for Tempo `hash` charge credentials, the transaction hash, and still returns the response. A 5xx without a receipt now keeps the provider's optimistic payment state, as a lost response does, instead of rolling it back.
