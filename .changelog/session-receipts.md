---
mpp: minor
---

Fixed Tempo session actions returning a base receipt that session clients such as mppx reject. `SessionMethod` now returns spec-shaped session receipts: `intent`, `challengeId`, `channelId`, `acceptedCumulative`, `spent`, `units` and, for `open`, `topUp` and `close`, `txHash` are carried as extension fields of the `Receipt`, so its `Payment-Receipt` header parses as a `SessionReceipt`. `reference` is now the channel ID for every action; code that read the open or close transaction hash from `reference` should read `txHash` instead. `SessionReceipt::to_base_receipt` keeps the session fields as well.
