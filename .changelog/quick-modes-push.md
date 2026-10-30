---
mpp: patch
---

Paid push-only Tempo charges as mppx's client does: when a non-zero challenge's `supportedModes` lists only `push`, the client broadcasts the transaction itself (without fee sponsorship) and sends a `hash` credential; `pull` is still preferred when offered. Added `TempoCharge::is_push`.
