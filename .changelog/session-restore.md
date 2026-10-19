---
mpp: minor
---

Added `TempoSessionProvider::restore`, which loads the channel a session challenge would pay from the durable store into memory, checked against chain state, without signing, so a client can prepare before its first paid request.
