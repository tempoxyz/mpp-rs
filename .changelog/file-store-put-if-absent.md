---
mpp: patch
---

Fixed `FileStore::put_if_absent` leaving an empty or truncated file behind when the write failed, which made the key look used forever. The value is now written to a temp file and hard-linked into place, so the key only exists once its contents are complete.
