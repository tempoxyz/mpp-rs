---
mpp: minor
---

Added Zone payments to the Tempo charge method, as mppx does: servers accept them with `TempoBuilder::zones` and verify the new `zone` Credential against the Zone portal's settlement on Tempo, and clients pay from a Zone balance with `TempoProvider::with_zone`. `TempoMethodDetails` gained a `zones` field and `PayloadType` a `Zone` variant, so exhaustive literals and matches need updating.
