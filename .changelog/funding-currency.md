---
mpp: minor
---

`PaymentResponseContext::funding_currency` reports the token the payer actually spent, through the new `PaymentProvider::funding_currency`. `TempoAccountsProvider` reports MACH when it pays a machine-token-enabled charge through the swapper and the autoswap input token when it swaps, so clients can label a charge correctly even when the server's receipt does not say how it was funded. MCP clients can read it from the provider before committing a payment.
