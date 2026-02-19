---
mpp: patch
---

Fixed potential `u64` overflow in `parse_gas_estimate` by using `checked_add` for the gas buffer. Added 46 new unit tests (432 → 478) covering signature variant correctness, encoding boundary conditions, escrow resolution priority, deposit edge cases, re-export verification, and gas estimate overflow protection.
