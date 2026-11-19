---
mpp: minor
---

Added TIP-1166 configurable account vouchers for TIP-1034 sessions: servers opt in with `SessionMethod::with_configurable_vouchers` (advertised as `configurableVouchers`) and track each channel's `opening_commitment`, and clients sign with `TempoSessionProvider::with_configurable_voucher_signer`. Session snapshot recovery checks a configurable voucher against the channel's opening commitment (`hydrate_session_snapshot_with_opening_commitment`). Defaults are unchanged. `ChannelState` gains the public `opening_commitment` field, so code that builds it with a struct literal must set it (`None` when unknown).
