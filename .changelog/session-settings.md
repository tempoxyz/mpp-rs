---
mpp: minor
---

`TempoAccountsProvider`'s `with_session_*` settings (deposit, top-up, maximum deposit, fee token, prepaid requests, events) no longer depend on the session store: they apply whether they are set before or after `with_session_store`, and survive a store change. A configured wallet's `with_sqlite_session_store(service)` is therefore that service's wallet, with the same settings and its own channels, instead of silently dropping settings set earlier.
