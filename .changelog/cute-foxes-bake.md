---
mpp: patch
---

Fixed fee-payer transaction signing in both the client provider and server broadcast path. The client now correctly serializes fee-payer transactions using the viem convention (0x00 placeholder, user signature appended, sender address + `feefeefeefee` suffix). The server now strips the suffix, decodes the wire format by patching the 0x00 placeholder to enable standard RLP decoding, applies the fee-payer signature, and re-encodes to canonical bytes before broadcasting.
