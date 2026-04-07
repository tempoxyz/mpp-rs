---
mpp: patch
---

Fixed busy loop in `serve()` caused by default `wait_for_update()` returning immediately instead of pending.
