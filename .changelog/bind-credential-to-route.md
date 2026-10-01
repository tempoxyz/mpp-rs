---
mpp: minor
---

Fixed the direct server verification API accepting a credential on a route it was not paid for. `Mpp::verify_credential` and `compose_verify` only check that the handler issued the challenge, so on a handler serving several prices a credential for the cheapest route unlocked all of them. Added `Mpp::verify_charge` and `Mpp::stripe_verify_charge` (plus `_with_options` variants), which take the amount the route charges and reject credentials issued for anything else, `Mpp::expected_charge_request` and `Mpp::stripe_expected_charge_request` for the `*_with_expected_request` methods, and `compose_verify_with_expected_requests`. `Mpp::verify_credential`, `Mpp::verify_credential_with_body` and `compose_verify` are deprecated. To migrate, replace `mpp.verify_credential(&credential)` with `mpp.verify_charge(&credential, amount)`, passing the amount the route gives to `charge()`.
