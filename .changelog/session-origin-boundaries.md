---
mpp: patch
---

Refused Tempo session challenges whose realm is not the request's hostname unless `with_trusted_tempo_proof_realm` pins it for that origin, as zero-amount proofs already were; a URL without an HTTP origin trusts only a pinned realm, as mppx does. Session providers bound to an HTTP origin no longer reuse or take over stored channels without an origin, and recovering a channel the store does not hold from a server snapshot now requires `TempoSessionProvider::with_origin`, as mppx does.
