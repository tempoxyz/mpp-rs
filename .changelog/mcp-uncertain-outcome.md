---
mpp: minor
---

Stopped the MCP client from paying another offer after a provider failure that cannot rule out a payment, such as a lost HTTP response or an accepted session top-up that could not be recorded. Added `MppError::UnknownPaymentOutcome` so providers of any method can report an unknown outcome without a transaction hash.
