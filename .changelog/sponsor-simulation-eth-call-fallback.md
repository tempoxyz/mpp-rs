---
mpp: patch
---

Fixed the Tempo fee payer broadcasting sponsored transactions without any pre-broadcast check when the node does not expose `tempo_simulateV1`, which includes the public `rpc.tempo.xyz` and `rpc.moderato.tempo.xyz` endpoints. The transaction's calls are now simulated with `eth_call` from the sender instead, so a transaction that would revert is rejected before the sponsor pays for it.
