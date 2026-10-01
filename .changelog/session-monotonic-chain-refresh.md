---
mpp: patch
---

Fixed the Tempo session method overwriting its stored channel with an older on-chain read. A voucher that awaited the chain while the channel was closed stored `finalized: false` again and was accepted, and a lagging node or two top-ups finishing out of order lowered the recorded deposit so vouchers within the real deposit were rejected. `finalized` now stays set and the recorded deposit only grows.
