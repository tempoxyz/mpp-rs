---
mpp: patch
---

Tempo charge receipts now report `fundingCurrency`, the token the payer spent, when the payment uses a recognized route: the payment currency for direct transfers, the DEX swap input token, or MACH for the machine-token swapper route. Transaction credentials read it from the signed transaction; final hash credential receipts look the transaction up once. Unrecognized routes, other senders, failed lookups and zero-amount proofs omit it without changing payment acceptance. Add `Receipt::with_funding_currency` and `Receipt::funding_currency`.
