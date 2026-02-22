---
mpp: minor
---

Added end-to-end support for the `0x78` fee payer envelope format, enabling clients to request gas sponsorship by sending a `0x78 || RLP(...)` encoded transaction that servers co-sign and broadcast as a standard `0x76` Tempo transaction. Extended server-side verification to accept both `0x76` and `0x78` transaction types, added `sign_and_encode_fee_payer_envelope` signing helpers, and added integration tests asserting on-chain fee payer and sender addresses.
