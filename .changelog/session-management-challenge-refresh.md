---
mpp: patch
---

Fixed `TempoSessionProvider::send_voucher` and `close` failing with `402` once the challenge of the last payment had expired, which is five minutes by default and shorter than many streams. Both now answer the fresh session challenge of a `402` response once, as top-ups already did. A challenge for a different payee, token, escrow or chain is refused.
