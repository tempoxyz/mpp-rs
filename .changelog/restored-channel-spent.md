---
mpp: patch
---

Fixed a session channel restored from the channel store, or through `bootstrap`, costing its first receipt at the Challenge's quoted price when no session snapshot seeded it. `TempoSessionProvider` now records the `spent` of each receipt in the store's `server_spent` column, which tempo-wallet also keeps, beside the channel's cumulative voucher amount, and a restored channel starts from it while those vouchers have not moved. `ChannelStore` gained `server_spent` and `set_server_spent`, whose defaults keep no record. `prime_prepaid` now replaces a recorded `spent` with the snapshot's.
