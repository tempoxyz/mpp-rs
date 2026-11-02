---
mpp: patch
---

Added `TempoProvider::from_signer`, a provider without its own RPC that, like mppx's client, pays on the chain each challenge names (`methodDetails.chainId`) through that chain's default RPC, on the pinned chain when the challenge names none, else on mainnet. Explicit pins are still enforced. Added `TempoProvider::with_allowed_chain_ids`: offers on other chains are skipped, and the chain actually signed on is checked before signing.
