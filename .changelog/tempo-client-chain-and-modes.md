---
mpp: minor
---

Fixed `TempoProvider` signing for whatever chain a challenge named, which let a server move a client configured with a testnet RPC onto mainnet funds. An unpinned provider now pays only on the chain its RPC reports (one cached `eth_chainId` request on the first payment), signs on that chain when the challenge omits `chainId`, and rejects any other chain with `ChainIdMismatch`. Call `with_expected_chain_id` to pin the chain without the lookup, e.g. when the RPC is not reachable while signing. Tempo charges also fail fast when a challenge's `supportedModes` does not list `pull` instead of sending a transaction credential the server rejects, and the transaction's `validBefore` is capped at the challenge `expires`.
