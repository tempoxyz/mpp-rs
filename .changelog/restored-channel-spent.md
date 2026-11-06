---
mpp: patch
---

Fixed a session channel restored from the channel store costing its first receipt at the Challenge's quoted price when the server sends no session snapshot. `TempoSessionProvider` now records the `spent` of each receipt in the store's `server_spent` column, which tempo-wallet also keeps, and a restored channel starts from it. `ChannelStore` gained `server_spent` and `set_server_spent`, whose defaults keep no record. `prime_prepaid` now replaces a recorded `spent` with the snapshot's.
