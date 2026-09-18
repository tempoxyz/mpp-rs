---
mpp: minor
---

Remove custom primary Tempo charge memos from `TempoMethodDetails` and `TempoChargeExt`. Clients always generate attribution memos bound to the challenge and realm, and servers always verify that binding. Split-specific memos remain supported.
