---
mpp: patch
---

Fixed `TempoSessionProvider::send_voucher` failing with `voucher cumulative amount exceeds channel deposit` when a `payment-need-voucher` event asked for more than the channel holds although `max_deposit` allowed a larger deposit. With `with_max_deposit` set it now tops the channel up first, as the spec requires and as `voucher_credential_with_top_up` already did, sized by `top_up_amount`, the server's `suggestedDeposit` and `max_deposit`. Without `max_deposit` the channel deposit stays the limit and the error is unchanged.
