---
mpay: patch
---

Refactored transaction verification to use `eth_sendRawTransactionSync` instead of separate broadcast and receipt fetch operations, eliminating redundant RPC calls and improving performance.
