---
mpp: minor
---

Added SDK helpers for session clients. `TempoAccountsProvider::with_sqlite_session_store` opens the shared SQLite channel store namespaced by a service's origin, and `TempoAccountsProvider::preconnect` sends an unpaid probe and restores the channel it would pay. `TempoSessionProvider::spend` reports what the server charged for requests paid through the provider and the deposit left, from payment receipts, and `TempoSessionProvider::stream_event` handles mppx `payment-need-voucher` and `payment-receipt` SSE events.
