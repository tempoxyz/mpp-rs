---
mpp: patch
---

Fixed `TempoSessionProvider` failing to open a channel on a legacy escrow contract with `native MPP channel is missing its descriptor`, a regression from 0.12.0. The failed open also left the channel tracked as open although it was never sent, so the next payment signed a voucher for a channel that does not exist. A failed open no longer leaves anything behind, and rolling back or invalidating a legacy channel no longer fails either.
