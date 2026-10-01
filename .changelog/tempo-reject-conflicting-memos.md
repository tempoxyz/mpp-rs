---
mpp: patch
---

Fixed Tempo charge verification accepting a payment when any matched transfer carried a memo bound to the challenge, even if another matched transfer carried an MPP attribution memo for a different challenge or server. Such conflicting attribution is now rejected, so one transaction cannot be credited to two challenges.
