---
mpp: patch
---

Fixed `sign_with` to refuse an attestation longer than the 8,192-character limit or with an empty key ID before calling the remote signer, and stopped `IdentityError::Signer` from repeating its cause in its message.
