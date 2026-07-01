---
mpp: minor
---

Sponsored (fee-payer) charges now dry-run the co-signed transaction via `tempo_simulateV1` before broadcasting. If the transaction would revert on-chain, the sponsor rejects it instead of paying gas for a failing transaction. The check fails closed: if the simulation RPC is unavailable, the charge is rejected.
