---
mpp: minor
---

Added a typed `Receipt::funding_currency` field so receipt parsing rejects a non-string `fundingCurrency`, matching mppx. `fundingCurrency` moved out of `Receipt::extensions` into the typed field: read it with `Receipt::funding_currency()` instead of `extensions["fundingCurrency"]`. An explicit `null` is now rejected, and an `extensions` entry with that key is no longer serialized.
