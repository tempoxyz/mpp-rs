---
mpp: patch
---

`TempoAccountsProvider` now applies its expected chain ID to session payments as it does to charges: a session challenge for another chain is rejected with `MppError::ChainIdMismatch` instead of being paid with the expected chain's key and RPC.
