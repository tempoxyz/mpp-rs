---
mpp: patch
---

Fixed cross-endpoint settlement replay vulnerability by verifying that the Transfer event's `from` field matches the transaction sender, preventing replay of session settlement transactions where the transfer originates from an escrow contract.
