---
mpp: patch
---

Fixed session `close` settling for less than was spent when units were deducted while the close was in flight. The close amount is now re-checked against the current `spent` in the same atomic update that marks the channel `closing`, and a close that no longer covers it is rejected.
