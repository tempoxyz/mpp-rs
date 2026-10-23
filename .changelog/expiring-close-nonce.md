---
mpp: patch
---

Signed server session close transactions with an expiring nonce instead of the close signer's sequential nonce, so independent server processes sharing a close signer no longer race for the same nonce.
