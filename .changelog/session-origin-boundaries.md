---
mpp: minor
---

Refused Tempo session challenges whose realm is not the request's hostname unless `with_trusted_tempo_proof_realm` pins it for that origin, as zero-amount proofs already were; a WebSocket URL is checked against its host, and any other URL, such as an MCP resource, trusts only a realm pinned for its scheme, host and port, as mppx does. Session providers bound to an HTTP origin no longer reuse or take over stored channels without an origin, and recovering a channel the store does not hold from a server snapshot now requires `TempoSessionProvider::with_origin` or `TempoAccountsProvider::with_session_origin`, as mppx does.

Migration: servers left on the default `"MPP Payment"` realm or a platform app-name realm must set `.realm(<host>)` or trusted request hosts so clients accept their session challenges, or clients must pin the realm with `with_trusted_tempo_proof_realm`. Stored channels written without an origin are no longer reused; delete them, or use a separate channel store per origin.
