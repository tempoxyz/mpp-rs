---
mpp: patch
---

Paid push-only Tempo charges as mppx's client does: when a non-zero challenge's `supportedModes` lists only `push`, the client broadcasts the transaction itself (without fee sponsorship) and sends a `hash` credential; `pull` is still preferred when offered. Added `TempoCharge::is_push`.

The payment flow never pays again after a 402 to a hash credential, since its transfer is already on chain. A push broadcast whose outcome is unknown reports its transaction hash and keeps a Tempo Accounts key authorization reserved while the chain shows the transaction or the installed key; it releases the authorization when the node rejected its parameters (-32602) or the chain shows neither. Nonce, replay and fee errors, EIP-7966 code 4 and transport failures may follow an earlier attempt the chain accepted.

The client re-checks the challenge's expiry right before broadcasting a push payment and refuses to pay an expired one. A server with a hosted fee payer and a store keeps the transaction the service co-signed under the client envelope's hash, so a retry after an unknown broadcast outcome reconciles that exact transaction instead of asking the service again.
