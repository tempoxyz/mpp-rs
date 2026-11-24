---
mpp: minor
---

Fixed paying from a Zone whose RPC redacts the outbox's `WithdrawalRequested` event from receipts, as mppx does, by deriving the candidate sender tags from the outbox's `lastFallbackNonce`. Added `zone::sender_tag_candidates`, `zone::wait_for_settled_withdrawal` and the `sender_tags` field of `MppError::ZoneSettlementPending`, which breaks struct literals and exhaustive patterns of that variant. A failed or timed-out sender tag read fails with `MppError::ZoneSettlementPending`, so retrying the challenge resumes it without withdrawing again. Both `lastFallbackNonce` reads are pinned to the hashes of the withdrawal's block and its parent, and a retry looks the transaction's receipt up again, deriving the tags from its new block if the Zone moved it.
