---
mpp: patch
---

Fixed TIP-1034 session credentials to name the channel's funding payer from the channel descriptor as their `source`, so a delegated voucher signer still identifies the funding account, as mppx does. Legacy escrow sessions keep naming the signing wallet, and a provider clone for another wallet no longer replays a pending open signed for the first.
