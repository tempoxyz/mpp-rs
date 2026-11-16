---
mpp: patch
---

Rejected received challenges and echoed credentials whose `header` auth-param is anything but `Payment-Authorization` (including an explicit `Authorization` or an empty value), skipping such challenges so another challenge in the same response can still be paid, as mppx does. `Payment-Authorization` is now stored, bound and emitted in its canonical spelling.
