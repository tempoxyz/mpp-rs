---
mpp: patch
---

Report errors that are not payment problems as the core spec's `internal-payment-error` with status 500, instead of the undefined `internal-error` type with status 402.
