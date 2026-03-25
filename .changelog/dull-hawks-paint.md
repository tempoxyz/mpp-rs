---
mpp: patch
---

Fixed two security vulnerabilities in the Tempo payment channel protocol: verified that Transfer event sender matches the transaction sender to prevent cross-endpoint settlement replay attacks, and used the on-chain settled amount when initializing new channel state to prevent double-spending of already-settled funds.
