---
mpp: minor
---

Added a structured `reason: Option<PaymentFailureReason>` field to `PaymentFailedContext`, marked the struct `#[non_exhaustive]`, and added `PaymentFailedContext::new()` and `with_reason()` constructors. Downstream callers should construct it via `new()` and destructure it with `..` so future field additions remain non-breaking.
