---
mpp: patch
---

Persist `FileStore::put_if_absent` via a synced temp file and rename so a mid-write failure cannot permanently poison replay-protection keys.
