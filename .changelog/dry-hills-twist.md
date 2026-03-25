---
mpp: patch
---

Fixed a bug where reopening an existing channel record did not bump `spent` to the `settled_on_chain` value, which could cause incorrect available-balance calculations. Added a regression test to cover this scenario.
