---
mpp: patch
---

Fixed session `close` reporting success without settling on-chain. A close whose transaction reverted is no longer recorded as finalized, and a `SessionMethod` without a close signer now rejects `close` instead of finalizing the channel in the store only. A failed close also no longer leaves the channel stuck in `closing`.
