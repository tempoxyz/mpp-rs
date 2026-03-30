---
mpp: patch
---

Fixed a timing side-channel in HMAC challenge ID verification by replacing non-constant-time string comparison with `constant_time_eq`. Added an `ast-grep` lint rule to prevent future regressions.
