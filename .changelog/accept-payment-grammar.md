---
mpp: patch
---

Fixed `accept_payment::parse` reading `Accept-Payment` weights loosely. The `q` parameter name is now matched case-insensitively, so `Q=0` is an opt-out instead of being ignored and treated as `q=1`. Values that are not HTTP qvalues (`.5`, `1e-1`, `+0.5`) and parameters without a value (`;q`) are rejected, and method tokens may contain the `:` and `_` that method names allow.
