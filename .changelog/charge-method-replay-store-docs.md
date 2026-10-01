---
mpp: patch
---

Documented that `TempoChargeMethod::new` configures no replay store, and updated the advanced API examples to add one with `with_store`. Without a store, a hash or proof credential is accepted again until its challenge expires.
