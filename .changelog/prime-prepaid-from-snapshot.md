---
mpp: minor
---

`TempoAccountsProvider::preconnect` primes the first prepaid voucher. After restoring a session channel, it asks the server again with a `Payment-Session` header naming that channel and reads the session snapshot in the challenge. `TempoSessionProvider::prime_prepaid` sizes the URL's first prepaid voucher from the snapshot's `spent`. The first request of a new process then carries its voucher instead of waiting for a `402`, and when earlier vouchers already cover the server's `spent` plus the request, it raises the cumulative amount by one unit instead of by the request's price. `TempoSessionProvider::restored_channel_id` reports the in-memory channel a challenge would pay from.
