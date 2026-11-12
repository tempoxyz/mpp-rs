---
mpp: patch
---

Fixed `funding_url_in` to keep only the `address` and `amount` parameters `funding_url` writes, so text around a MACH funding link in a problem's `detail` can't change the `fundingUrl` it reports.
