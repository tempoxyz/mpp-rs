---
mpp: patch
---

Added identity, as mppx's `mppx/identity` does, behind the new `identity` feature: server-side `Verifier`s that run before any 402 and a `PaymentCheck` that runs on the paid retry before the Credential settles, combined with `any_of` and built with `from_fn`, with mppx's fixed rejection statuses (`missing` and `invalid` 401, `forbidden` 403, `unavailable` 503) and `Identity-Required` header. The Axum extractors run a route's `RouteIdentity` request extension and expose `charge.identity`. On the client, `ChargeClient::with_identity` applies `Prover`s to every attempt.

Added Tempo ID as an identity method behind the `identity-tempo-id` feature, as mppx's `mppx/extensions/identity/tempo` does: `tempo_id::server::create` verifies Tempo ID access tokens offline, with DPoP proofs, and returns a payment check that requires a `tempo` payment from a cleared Tempo Account the token grants to the app; `tempo_id::client::prover` sends the access token, a DPoP proof per request and the optional ID token.
