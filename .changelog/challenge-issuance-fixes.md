---
mpp: patch
---

Fixed `Mpp::charge_challenge` and `Mpp::charge_challenge_with_options` issuing challenges without `chainId` on handlers built with `Mpp::create`, which the same handler then rejected with `credential chainId None does not match`. They now add the handler's chain ID like `charge()` does; a `chainId` already present in the request is kept.
