---
mpp: patch
---

Fixed session credentials to name the channel's funding payer from the channel descriptor as their `source`, so a delegated voucher signer still identifies the funding account, as mppx does.
