---
mpp: patch
---

Removed the 16 KiB size cap from `Payment-Receipt` parsing so receipts with large method-specific fields parse, matching mppx.
