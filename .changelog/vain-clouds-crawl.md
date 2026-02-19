---
mpp: minor
---

Added fee payer (0x78 envelope) support to the Tempo payment provider. The client now encodes fee payer transactions in the 0x78 format using expiring nonces, and the server co-signs them by recovering the sender, setting the fee token, and re-encoding as a standard 0x76 transaction with both signatures.
