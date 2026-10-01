---
mpp: patch
---

Fixed the Tempo charge server ignoring `methodDetails.supportedModes`: a credential whose mode the challenge does not advertise (a hash credential for a pull-only challenge, or a transaction credential for a push-only one) is now rejected. `ChargeOptions::supported_modes` values other than `"pull"`/`"push"` are rejected when the challenge is created.
