---
mpp: patch
---

Fixed sponsored charges failing pre-broadcast simulation with "insufficient fee token balance" on Tempo nodes v1.18 and later, which bill the fee payer recovered from `feePayerSignature` in `eth_call` and the sender when it is absent. The final sponsored simulation now sends the fee payer's signature, as mppx does: a hosted fee payer's as returned, and a local fee payer's over a simulation-only copy with 10,000 more gas, signed only after the sender's calls pass simulation. The broadcast transaction keeps its gas limit.
