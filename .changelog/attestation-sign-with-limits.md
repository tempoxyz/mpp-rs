---
mpp: patch
---

Fixed `sign_with` to refuse, before calling the remote signer, an attestation the SDK could not decode (longer than 8,192 characters, with an empty key ID, or with claims that are not a JSON object or are nested too deeply), and stopped `IdentityError::Signer` from repeating its cause in its message.
