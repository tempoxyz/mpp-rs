---
mpp: minor
---

Added fee payer support to the Tempo payment provider. The client now builds 0x76 transactions with expiring nonces and a placeholder fee payer signature, and the server co-signs them by recovering the sender, setting the fee token, and re-encoding as a standard 0x76 transaction with both signatures.
