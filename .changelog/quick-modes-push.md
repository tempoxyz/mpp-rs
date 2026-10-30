---
mpp: patch
---

Paid push-only Tempo charges as mppx's client does: when a non-zero challenge's `supportedModes` lists only `push`, the client broadcasts the transaction itself (without fee sponsorship) and sends a `hash` credential; `pull` is still preferred when offered. Added `TempoCharge::is_push`.

The payment flow never pays again after a 402 to a hash credential, since its transfer is already on chain. A push broadcast keeps a Tempo Accounts key authorization reserved, and reports its transaction hash, unless the node rejects its parameters (-32602): nonce, replay and fee errors, EIP-7966 code 4 and transport failures may follow an earlier attempt the chain accepted.
