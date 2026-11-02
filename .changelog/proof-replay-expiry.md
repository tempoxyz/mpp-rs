---
mpp: minor
---

Expire proof replay reservations after challenge expiry plus clock skew. Reclaim expired in-memory reservations with an ordered expiry index and fail closed at the configurable live-reservation limit. Stores without TTL support continue retaining reservations atomically; non-expiring challenges retain permanent markers.

Only HMAC-authenticated server verification expires proof reservations; direct verification retains permanent markers. Memory expiry uses the wall clock consistently with challenge acceptance. The global live-entry cap is opt-in through `MemoryStore::with_expiring_capacity`, so a public proof endpoint does not acquire a default global lockout threshold.

A shared replay store permanently records when authenticated proof expiry is enabled. All proof consumers of that store must then use HMAC-authenticated server verification; direct consumers fail closed so removing an echoed expiry cannot resurrect a consumed proof after marker reclamation. The domain marker is one permanent entry per store, not one per challenge.

Breaking change for mixed proof consumers: migrate every consumer of a shared expiring replay store to the HMAC-authenticated `Mpp` verification path before accepting proofs after upgrade. Direct-only stores continue retaining permanent markers. Do not delete the domain marker to restore direct verification: previously expired proof records cannot be recovered that way.
