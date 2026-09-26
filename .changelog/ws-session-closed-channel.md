---
mpp: patch
---

Fixed `ws_session` looping on `needVoucher` forever once the channel is finalized or closing. It now emits the final session receipt and returns, matching the SSE session loop.
