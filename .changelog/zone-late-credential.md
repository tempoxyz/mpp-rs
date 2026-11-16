---
mpp: patch
---

Changed Zone payments to resume a pending withdrawal instead of withdrawing again, as mppx does: a Credential made after its Challenge expired is reused only for that Challenge, other Challenges with the same terms fail with `ZoneSettlementPending` until its redemption window ends, and an expired Challenge is refused before paying. Servers now honor `zone_credential_grace` only for Challenges issued with it, which carry the `_mppx_expiry_grace` marker in their `opaque`, and refuse it with a relay. `Mpp::new` also honors a charge method's own grace and relay, read through the new `ChargeMethod::zone_credential_grace` and `verifies_zone_credentials` hooks. A Zone payment dropped before its withdrawal was sent no longer sends it.
