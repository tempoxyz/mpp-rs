---
mpp: patch
---

Expire proof replay reservations after challenge expiry plus clock skew. Reclaim expired in-memory reservations with an ordered expiry index and fail closed at the configurable live-reservation limit. Stores without TTL support continue retaining reservations atomically; non-expiring challenges retain permanent markers.

Only HMAC-authenticated server verification expires proof reservations; direct verification retains permanent markers. Memory expiry uses the wall clock consistently with challenge acceptance. The global live-entry cap is opt-in through `MemoryStore::with_expiring_capacity`, so a public proof endpoint does not acquire a default global lockout threshold.
