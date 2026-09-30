---
"mpp": patch
---

Parse challenge auth-param names case-insensitively, so `Realm=` or `ID=` are accepted and case-variant duplicates such as `id=` and `ID=` are rejected.
