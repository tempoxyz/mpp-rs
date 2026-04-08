---
mpp: patch
---

Use `eth_sendRawTransactionSync` (EIP-7966) instead of `eth_sendRawTransaction` + polling for receipt. The Tempo node returns the full receipt in a single blocking call, eliminating the client-side polling loop and reducing broadcast latency from 0.5–7.5s to ~500ms.
