---
mpp: minor
---

Fixed `Mpp::create` accepting `.fee_payer(true)` with neither a fee payer signer nor a relay: every challenge advertised `feePayer: true` and every sponsored credential was then rejected. This configuration now fails with `InvalidConfig`. To migrate, add `.fee_payer_signer(...)` or `.relay(...)`, or drop `.fee_payer(true)`.
