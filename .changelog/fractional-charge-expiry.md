---
mpp: patch
---

Tempo charge transactions now cap `validBefore` at the second after the challenge `expires` instead of flooring it, so a fractional or current-instant expiry no longer yields an already-passed deadline.
