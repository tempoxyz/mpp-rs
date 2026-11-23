---
mpp: minor
---

Fixed paying from a Zone whose RPC redacts the outbox's `WithdrawalRequested` event from receipts, as mppx does: the client now derives the candidate sender tags from the outbox's `lastFallbackNonce` and matches the portal's `WithdrawalProcessed` event on Tempo for any of them. A failed read of the sender tag is retried with the Challenge, without withdrawing again. Added `zone::sender_tag_candidates` and `zone::wait_for_settled_withdrawal`, and `MppError::ZoneSettlementPending` gained `sender_tags`, every candidate tag, with `sender_tag` empty when more than one remains, so struct literals and exhaustive patterns of that variant need updating.
