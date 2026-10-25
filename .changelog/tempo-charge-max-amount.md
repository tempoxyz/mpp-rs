---
mpp: minor
---

Added `with_currencies`, `with_max_amount` and `with_max_atomic_amount` to `TempoProvider` so clients skip and refuse charges in other currencies or above a per-charge cap. `MultiProvider` now falls through to the next payment method when a provider rejects all of its offers.
