---
mpp: patch
---

Enforced fail-closed behavior for the `expires` field in `verify_hmac_and_expiry`. Credentials missing the `expires` field are now rejected with a `CredentialMismatch` error instead of being silently accepted. Session challenges now include a default expiry.
