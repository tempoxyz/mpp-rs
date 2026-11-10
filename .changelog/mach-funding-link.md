---
mpp: minor
---

Added Tempo Wallet's MACH funding link for payers short of MACH on Tempo mainnet, as mppx does. `machine_token::funding_url` builds it (`MACH_FUNDING_URL` with the payer's `address` and the `amount` to buy, rounded up to cents). Clients paying a MACH charge, a `machineTokenEnabled` charge or a MACH session deposit without enough MACH now return `TempoClientError::InsufficientBalance` naming the MACH shortfall, with the link in its message and in the new `funding_url` field (also `MppError::funding_url`). Servers append the link to `session/insufficient-balance` problems on MACH channels whose deposit cannot cover a charge, and problem details carry it as the optional `fundingUrl` extension member (`PaymentErrorDetails::funding_url`). `TempoClientError::InsufficientBalance` and `PaymentErrorDetails` gained a field, so code that builds them with struct literals must set it.
