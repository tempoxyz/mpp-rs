---
mpp: patch
---

Fixed session challenges advertising `feePayer: true` and a machine-token settlement route whenever the handler had fee sponsorship or machine tokens enabled for charges. The Tempo session method can honour neither, so every session open or top-up from a client that followed the advertisement failed. Session challenges now only advertise them when the session method opts in through the new `SessionMethod::supports_fee_payer` and `SessionMethod::supports_machine_tokens` hooks (both default to `false`); charge challenges are unchanged.
