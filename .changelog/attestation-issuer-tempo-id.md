---
mpp: patch
---

Added `AttestationIssuer`, which signs audience-bound identity attestations of any type with an Ed25519 key and serves its JSON Web Key Set, and the optional `uid` and `cnf` attestation claims (`AttestationClaims::uid`, `AttestationClaims::cnf`), which `verify` now checks for shape, so one issuer can attest several linked accounts of one user, as mppx does. Added `tempo_id::issuer::create`, which exchanges a Tempo ID access token for `tempo-id` and `email` attestations, and `tempo_id::client::attestations` and `tempo_id::client::attest`, which obtain them, as mppx's `TempoId.Issuer` and `TempoId.Client.attestations`.
