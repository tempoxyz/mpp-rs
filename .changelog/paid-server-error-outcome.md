---
mpp: patch
---

When a paid retry returns a 5xx response or fails to send, the client now emits `payment.failed` with `PaymentFailureReason::OutcomeUnknown`, carrying the status, the serialized credential and, for Tempo `hash` charge credentials, the transaction hash, and still returns the response.
