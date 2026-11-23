---
mpp: patch
---

Fixed `sign_with` to refuse an attestation longer than the 8,192-character limit before calling the remote signer, and stopped `IdentityError::Signer` from repeating its cause in its message.
