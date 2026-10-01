---
mpp: minor
---

Fixed the proxy's OpenAPI discovery document omitting the payment method. `proxy::PaidEndpoint` has a new `method` field, written as `method` in each `x-payment-info` offer (REQUIRED by the discovery spec) and in the `payment` object of `/services`.

Migration: `PaidEndpoint` is now `#[non_exhaustive]`, so it can no longer be built with a struct literal. Use `PaidEndpoint::new(method, intent, amount)` and the `with_decimals`, `with_currency`, `with_unit_type` and `with_description` setters, e.g. `PaidEndpoint::new("tempo", "charge", "50000").with_decimals(6)`.
