---
mpp: patch
---

Fixed pre-broadcast transaction deduplication by computing and checking the tx hash before broadcasting to prevent duplicate submissions. Fixed cross-endpoint replay of session settlement transactions by verifying that the Transfer event's `from` field matches the transaction sender. Fixed case-insensitive replay key handling for transaction hashes.
