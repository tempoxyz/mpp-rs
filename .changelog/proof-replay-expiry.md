---
mpp: patch
---

Expire proof replay reservations after challenge expiry plus clock skew. Reclaim expired in-memory reservations with an ordered expiry index and fail closed at the configurable live-reservation limit. Stores without TTL support continue retaining reservations atomically; non-expiring challenges retain permanent markers.
