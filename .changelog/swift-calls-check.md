---
mpp: patch
---

Simulated sponsored Tempo charges as mppx does, with two `eth_call`s instead of `tempo_simulateV1`: the sender's calls alone (no fee fields or signatures) before any sponsor signs, then the co-signed transaction with its concrete `feePayer` and `feeToken` before broadcasting. A reverting transaction never reaches the fee payer.
