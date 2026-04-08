---
mpp: patch
---

Cache chain ID in `ChargeMethod` to avoid a redundant `eth_getChainId` RPC call (~270ms) on every `verify()` invocation. The chain ID is fetched once on the first call and reused for all subsequent verifications.
