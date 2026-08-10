---
"mpp": patch
---

Mark successful body-bound payment responses as private while preserving existing
`Cache-Control` directives, preventing shared caches from storing payment receipts.
