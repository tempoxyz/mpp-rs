---
mpp: minor
---

Added fee-payer envelope encoding support for Tempo clients. Introduced a new `fee_payer` module with helpers to build placeholder fee-payer signatures and encode fee-payer proxy transactions (prefixed with magic byte `0x78`). Updated `TempoProvider::pay` to use `TempoTransactionRequest` for transaction building and conditionally encode the fee-payer envelope when fee sponsorship is enabled.
