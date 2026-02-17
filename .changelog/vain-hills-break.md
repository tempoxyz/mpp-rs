---
mpp: patch
---

Fixed support for fee-payer-sponsored Tempo transactions by setting placeholder fee payer signatures in the client, appending sender address with magic bytes for server identification, and normalizing viem-encoded transactions that use `0x00` instead of `0x80` for empty fee payer signature placeholders.
