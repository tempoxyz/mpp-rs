---
mpp: minor
---

Add `ChargeMethod::validate_expected_request` so payment methods can compare
selected method-specific fields against a route's expected charge request before
validation or broadcast. The default accepts additional fields, preserving
existing methods, and all existing core comparisons and credential checks remain
in place.
