---
mpp: patch
---

Fixed a sponsored Tempo session open, top-up or legacy open that also authorizes the signing access key failing on chain with "intrinsic gas too low": it declared the fixed 2,000,000 gas of any sponsored session transaction, far below what installing a key costs. Such transactions now declare 20,000,000 gas, within the 25,000,000 that fee payers such as Tempo Gateway sponsor; sponsored transactions without a key authorization keep 2,000,000.
