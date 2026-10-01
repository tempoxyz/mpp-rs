---
mpp: patch
---

Fixed `TempoSessionProvider` resuming a legacy channel suggested by the server without checking that the remaining deposit covers the request, which signed a voucher above the deposit, and panicking in debug builds when the settled amount plus the request amount overflowed. Such a channel is no longer resumed and a new one is opened instead.
