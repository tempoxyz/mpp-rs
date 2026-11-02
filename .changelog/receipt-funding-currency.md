---
mpp: minor
---

Added a typed `Receipt::funding_currency` field so receipt parsing rejects a non-string `fundingCurrency`, matching mppx.
