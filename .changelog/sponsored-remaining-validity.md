---
mpp: patch
---

Require at least 15 seconds of remaining validity (`valid_before`) before co-signing a fee-sponsored Tempo charge transaction and again before broadcasting it, matching mppx, so the sponsor does not pay for a transaction that can expire in flight.
