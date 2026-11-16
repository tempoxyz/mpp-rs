---
mpp: patch
---

Changed Zone payments to resume a pending withdrawal instead of withdrawing again, as mppx does: a Credential made after its challenge expired is reused only for that challenge, other challenges with the same terms fail with `ZoneSettlementPending` until its redemption window ends, and an expired challenge is refused before paying. Servers now honor `zone_credential_grace` only for challenges issued with it, which carry the `_mppx_expiry_grace` marker in their `opaque`, and refuse it with a relay.
