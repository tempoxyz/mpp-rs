---
mpp: patch
---

Fixed `TempoChargeMethod::new` accepting a hash or proof Credential more than once: it now defaults to an in-memory replay store, as `Mpp::create` does, and `TempoChargeMethod::without_store` removes it.
