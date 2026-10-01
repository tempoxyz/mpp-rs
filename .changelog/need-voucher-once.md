---
mpp: minor
---

Fixed `sse::serve` and `ws_session` repeating the need-voucher event on every poll tick and channel write while the balance was exhausted. It is now sent once per exhaustion, as mppx does, so clients no longer answer with duplicate vouchers. `requiredCumulative` now also clears the server's minimum voucher delta, so a stream no longer stalls when that delta is larger than the tick cost. `ServeOptions` and `WsSessionOptions` have a new required `min_voucher_delta` field: set it to the session method's `SessionMethodConfig::min_voucher_delta` (`0` if none is enforced).
