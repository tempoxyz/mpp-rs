---
mpp: minor
---

Added prepaid session vouchers. `TempoSessionProvider::with_prepaid_requests` (and `TempoAccountsProvider::with_session_prepaid_requests`) keep a few requests' worth of balance, at the latest request's price, prepaid on the channel, and send the voucher with the next request to the same URL instead of waiting for a `402`. This needs a server whose session challenges are reusable (mppx `reusableChallenges`); any `402` falls back to the normal flow. `PaymentProvider` gains the `prepaid_credential` and `observe_receipt` hooks the payment flow uses for this.
