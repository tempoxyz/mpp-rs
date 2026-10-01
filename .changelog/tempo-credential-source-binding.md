---
mpp: patch
---

Fixed the Tempo charge method never checking `credential.source` on transaction (pull) credentials, so `ChargeValidation::source` reported whatever payer the client claimed. A `source` that is not a `did:pkh:eip155` DID for the challenge chain naming the recovered transaction sender is rejected now, before fee-payer co-signing and broadcast. When `source` is omitted, `ChargeValidation::source` reports the recovered sender.
