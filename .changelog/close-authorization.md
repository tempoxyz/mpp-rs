---
mpp: patch
---

TIP-1034 close credentials carry the cooperative close authorization (`closeSignature`), a distinct EIP-712 `CloseAuthorization` signature over the channel and amount that mppx servers have required since 0.13.1. Without it, `TempoSessionProvider::close` and `close_with` were rejected by mppx 0.13 and 0.14 servers, including tempoxyz/mpp-proxy and Mercator. `precompile_close_authorization_signing_hash_with_escrow` and the `sign_precompile_close_authorization*` functions are exported, and the hash matches viem's for mppx's typed data.
