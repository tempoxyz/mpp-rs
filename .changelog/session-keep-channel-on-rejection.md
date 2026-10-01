---
mpp: patch
---

Fixed the Tempo session client forgetting an established channel whenever a voucher was answered without a receipt (any `402`, `5xx` or `429`), which opened a second channel on the next request and stranded the first deposit. `TempoSessionProvider::rollback_payment` now only discards a channel whose open was never accepted. A channel is forgotten when the server answers `410 Gone`, reported through the new `PaymentProvider::invalidate_payment` hook, which defaults to `rollback_payment`.
