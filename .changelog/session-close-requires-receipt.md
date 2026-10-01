---
mpp: patch
---

Fixed `TempoSessionProvider::close` forgetting the channel on any successful response. A `2xx` without a `Payment-Receipt` no longer removes the channel from memory and the channel store, so a close the server did not confirm can be retried instead of leaving a funded channel untracked.
