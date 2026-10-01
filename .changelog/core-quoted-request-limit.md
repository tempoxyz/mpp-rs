---
mpp: patch
---

Fixed the challenge parser rejecting a quoted `request` parameter of exactly 16384 bytes as too long. The limit is now the same for quoted and unquoted values, and the same as in mppx.
