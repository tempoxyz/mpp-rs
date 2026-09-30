---
mpp: patch
---

Fixed `sse::serve` and `ws_session` polling forever when the channel is missing or the store fails. Only an insufficient balance now waits for a voucher; any other deduction error emits the final session receipt (if the channel is still readable) and stops.
