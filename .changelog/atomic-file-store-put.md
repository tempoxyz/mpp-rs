---
mpp: patch
---

Fixed `FileStore::put` overwriting the key file in place, which let concurrent readers observe an empty or truncated value and could leave a corrupt file behind after a crash. The value is now written to a temp file and renamed over the key, so readers always see a complete value.
