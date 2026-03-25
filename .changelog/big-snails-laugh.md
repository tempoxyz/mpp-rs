---
mpp: patch
---

Fixed cross-endpoint replay attack vector by verifying that the Transfer event's `from` field matches the transaction sender, preventing session settlement transactions (where the transfer originates from an escrow contract) from being replayed. Added pre-broadcast deduplication by computing and storing the transaction hash before submission.
