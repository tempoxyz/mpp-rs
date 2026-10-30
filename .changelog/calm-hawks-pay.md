---
mpp: minor
---

Sponsored Tempo charges by default whenever a fee payer is configured, as mppx does. `ChargeOptions::fee_payer` is now an `Option<bool>`: `None` follows the handler, `Some(false)` opts a route out and `Some(true)` sponsors it when the handler can; a handler without a fee payer never advertises `feePayer`. `TempoBuilder::fee_payer(false)` turns default sponsorship off. Push-only sponsored challenges, like zero-amount ones, are no longer held to the 15-second issuance floor.
