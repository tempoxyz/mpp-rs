---
mpp: patch
---

Accept the RFC 9530 SHA-256 byte-sequence form when verifying body-bound
payment credentials, alongside the existing bare digest form. Digest generation
and the exact text bound into challenge IDs remain unchanged.
