---
mpp: patch
---

Added an ERC-8004 agent identity provider behind the new `identity-erc8004` feature, as mppx's `mppx/extensions/identity/erc8004` does: `identity::ext::erc8004::server::create` verifies requests signed by an agent's registered wallet, or paid from it, and `identity::ext::erc8004::client::prover` signs them. `Agent-Id` and `Agent-Signature` are now treated as identity headers, so they don't cross origins or reach upstreams. The payment check runs `allow` only on an agent that signed the request, and `Config::require_signature` makes it require the signature on every paid retry.
