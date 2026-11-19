---
mpp: minor
---

Payment method names are now limited to lowercase letters (a-z), as the spec grammar `1*LOWERALPHA` requires: parsing and formatting a Challenge, and deserializing a `MethodName` in a Credential or Receipt, reject names with digits, `:`, `_` or `-`. Rename custom methods that use them.
