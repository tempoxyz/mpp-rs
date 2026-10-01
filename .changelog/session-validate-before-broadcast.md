---
mpp: patch
---

Fixed Tempo session servers broadcasting client transactions before validating the credential. An `open` whose voucher has an invalid signature or exceeds the deposit is now rejected before its transaction is sent, instead of leaving a funded channel the server never recorded. A `topUp` transaction is now decoded and must be a Tempo transaction calling `topUp` on the escrow for the credential's channel and `additionalDeposit`; previously any signed transaction was relayed.
