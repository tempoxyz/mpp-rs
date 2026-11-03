---
mpp: patch
---

Added `with_currencies`, `with_max_amount`, `with_max_atomic_amount` and `with_expected_recipients` to `TempoSessionProvider`, as mppx's session spending options do. Session offers in other currencies, to unexpected recipients or with a per-unit amount above the cap are skipped during Challenge selection and rejected before signing a Credential or topping up a channel; explicit closes stay allowed for any offer.
