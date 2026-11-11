---
mpp: patch
---

Fixed `TempoChargeMethod::new` accepting a hash Credential more than once: it now defaults to an in-memory replay store, as `Mpp::create` does, and `TempoChargeMethod::without_store` removes it. Zero-amount proofs verified through `Mpp` are single-use in a separate store whose entries expire with their Challenge; proofs verified directly need `with_store`.
