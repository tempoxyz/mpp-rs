---
mpp: patch
---

Fixed `sign_with` to refuse, before calling the remote signer, an attestation longer than the 8,192-character limit, an empty key ID, or claims that are not a JSON object, and stopped `IdentityError::Signer` from repeating its cause in its message.
