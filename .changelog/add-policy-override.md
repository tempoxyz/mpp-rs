---
mpp: minor
---

Added `ChargeMethod::with_fee_payer_policy_override()` for per-server tuning of the fee-sponsor policy (`max_gas`, `max_fee_per_gas`, `max_priority_fee_per_gas`, `max_total_fee`, `max_validity_window_seconds`), with per-chain defaults matching mppx#342.
