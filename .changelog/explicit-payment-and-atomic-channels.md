---
mpp: minor
alloy-transport-mpp: minor
---

Require explicit HTTP request payment preferences by default; opaque reqwest client defaults cannot trigger automatic payments. Add `AcceptPaymentPolicy::Explicit` and `Disabled`. Set request-level `Accept-Payment`, or opt into provider-selected payment with `Always`. Channel store adapters now require native atomic compare-and-exchange; unsupported backends fail closed. Prevent unconfirmed channel opens from increasing cumulative vouchers before settlement reconciliation.
