---
mpp: patch
---

Fixed Tempo hash-credential verification counting the `Transfer` and `TransferWithMemo` logs of a single `transferWithMemo` call as two transfers, which let one transfer satisfy two expected transfers of a split payment. The pair is now matched as a single transfer.
