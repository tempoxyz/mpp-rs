---
mpp: patch
---

Fixed session channels being charged after the payer requested a forced close. `deduct_from_channel` now rejects a channel with a pending close request, as it already did for a closing or finalized one, so `sse::serve` and `ws_session` stop with the final receipt instead of delivering service the payer can withdraw before it is settled.
