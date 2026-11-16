---
mpp: minor
---

Added Zone payments to the Tempo charge method, as mppx does: servers accept them with `TempoBuilder::zones` (and, with `TempoBuilder::zone_credential_grace`, a late `zone` Credential whose withdrawal settled before its Challenge expired) and verify the new `zone` Credential against the Zone portal's settlement on Tempo, and clients pay from a Zone balance with `TempoProvider::with_zone`, resuming an outstanding withdrawal instead of paying the same terms twice. `TempoMethodDetails` gained a `zones` field and `PayloadType` a `Zone` variant, so exhaustive literals and matches need updating.
