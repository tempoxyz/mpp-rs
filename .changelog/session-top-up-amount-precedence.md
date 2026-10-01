---
mpp: patch
---

Fixed `TempoSessionProvider::with_top_up_amount` being ignored whenever the server's `suggestedDeposit` was larger, so an automatic top-up deposited the server's amount instead of the configured one. The configured amount now takes precedence; a top-up still covers at least the shortfall and stays within `max_deposit`.
