---
mpp: patch
---

Paid push-only Tempo charges as mppx's client does: when a non-zero challenge's `supportedModes` lists only `push`, the client broadcasts the transaction itself (without fee sponsorship) and sends a `hash` credential; `pull` is still preferred when offered. Added `TempoCharge::is_push`.

The payment flow never pays again after a 402 to a hash credential, since its transfer is already on chain. A push broadcast whose node answer leaves the outcome unknown (EIP-7966 code 4, "already known" or a transport failure) keeps a Tempo Accounts key authorization reserved; only a refusal releases it.
