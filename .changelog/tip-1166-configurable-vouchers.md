---
mpp: patch
---

Added TIP-1166 configurable account vouchers for TIP-1034 sessions: servers opt in with `SessionMethod::with_configurable_vouchers` (advertised as `configurableVouchers`) and track each channel's `opening_commitment`, and clients sign with `TempoSessionProvider::with_configurable_voucher_signer`. Defaults are unchanged.
