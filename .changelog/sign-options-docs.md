---
mpp: patch
---

Fixed the `SignOptions` docs, which described defaults the Tempo charge client does not use: `nonce_key` defaults to `U256::MAX` (expiring nonce) rather than `U256::ZERO`, `nonce` to `0` rather than a fetched pending nonce, the gas fees to static values rather than the latest base fee, and `valid_before` applies to every charge.
