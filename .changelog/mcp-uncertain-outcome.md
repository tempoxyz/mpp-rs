---
mpp: minor
---

Changed the MCP client to pay only the best-ranked offer and return its error, as mppx does, instead of paying another offer after a failure that might already have moved funds. Added `MppError::UnknownPaymentOutcome` so providers of any method can report an unknown outcome without a transaction hash.
