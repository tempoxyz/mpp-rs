---
mpp: patch
---

Sessions now read on-chain channel state concurrently with the stored channel when accepting a voucher; stored-channel errors still take precedence over a failed on-chain read.
