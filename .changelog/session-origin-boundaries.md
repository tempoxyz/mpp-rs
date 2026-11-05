---
mpp: minor
---

Refused Tempo session challenges whose realm is not the request's hostname unless `with_trusted_tempo_proof_realm` pins it for that origin, as zero-amount proofs already were; a WebSocket URL is checked against its host, and any other URL, such as an MCP resource, trusts only a realm pinned for its scheme, host and port, as mppx does. Session providers bound to an HTTP origin no longer reuse or rebind stored channels without an origin: such a legacy entry reads as absent and is replaced by the next channel the provider opens, and recovering a channel the store does not hold from a server snapshot now requires `TempoSessionProvider::with_origin` or `TempoAccountsProvider::with_session_origin`, as mppx does.

Migration: servers left on the default `"MPP Payment"` realm or a platform app-name realm must set `.realm(<host>)` or trusted request hosts so clients accept their session challenges, or clients must pin the realm with `with_trusted_tempo_proof_realm`. Stored channels written without an origin are no longer reused once a provider is bound; close them to reclaim their deposits, or pin the provider with `with_origin` before its first payment so the channels it writes carry an origin.
