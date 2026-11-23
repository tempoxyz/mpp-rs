---
mpp: patch
---

Added `attestation::sign_with` and the `RemoteSigner` trait, so issuers can sign attestations with an Ed25519 key that stays in a cloud KMS, an HSM or a wallet service, as mppx's `Attestation.sign` does. Each remote signature is verified against the signer's public key before it is used, and the `kid` defaults to the key's RFC 7638 `thumbprint`.
