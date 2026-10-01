---
mpp: patch
---

Fixed the session server accepting voucher signatures the escrow contract cannot settle: high-s signatures and signatures with trailing bytes (such as the Tempo envelope magic trailer) are now rejected with `invalid-signature`. Vouchers must be a 65-byte `r || s || v` signature with `v` of 27 or 28, or a 64-byte EIP-2098 compact signature, and are stored in the 65-byte form.
