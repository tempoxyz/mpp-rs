---
mpp: patch
---

Fixed Tempo transactions that also authorize the signing access key failing with "intrinsic gas too low" or a failed gas estimate: installing a key can cost over 18,000,000 gas. A sponsored session open, top-up or charge, and a legacy session open, now declare 20,000,000 gas when they carry a key authorization (within the 25,000,000 that fee payers such as Tempo Gateway sponsor), and an unsponsored one estimates its gas under that limit rather than 3,000,000. Transactions without a key authorization are unchanged.
