---
mpp: patch
---

Preserve Unicode in challenge auth-params by encoding non-Latin-1 text as UTF-16 escapes and decoding those escapes while parsing.
