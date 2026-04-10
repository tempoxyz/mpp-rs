---
mpp: patch
---

Fixed `credential.source` DID mismatch between $0 proofs and paid charges in Keychain signing mode. The proof path now uses the wallet address (matching mppx and the paid charge path). Server-side `verify_proof` falls back to an on-chain keychain lookup when the recovered signer differs from the source address.
