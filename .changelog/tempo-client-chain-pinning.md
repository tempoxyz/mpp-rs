---
mpp: patch
---

Add client-side Tempo chain pinning. `TempoProvider::with_expected_chain_id` rejects charge challenges whose `methodDetails.chainId` conflicts with the configured chain ID, and signs on the pinned chain when the challenge omits it — matching the mpp-go conformance ABI.
