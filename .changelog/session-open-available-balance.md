---
mpp: patch
---

Fixed session `open` accepting a channel that cannot pay for a single unit. The open transaction's deposit, and the channel's available balance once it is on-chain, must now cover the challenge `amount`; an open below it is rejected with `insufficient-balance` before the transaction is broadcast.
