---
mpp: patch
---

Fixed `TempoChargeMethod::new` keeping a permanent in-memory marker for every zero-amount proof Credential verified directly: its default store now covers hash Credentials only, and `with_store` still makes proofs single-use.
