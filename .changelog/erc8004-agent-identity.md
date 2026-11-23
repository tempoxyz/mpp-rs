---
mpp: patch
---

Added an ERC-8004 agent identity provider, as mppx's `mppx/extensions/identity/erc8004` does, behind the new `identity-erc8004` feature. On the server, `identity::ext::erc8004::server::create` returns a `verifier` that reads the agent's wallet from the Identity Registry (`getAgentWallet`, on Tempo mainnet by default) and checks the request's `Agent-Signature` by EOA recovery or ERC-1271, valid for five minutes and, with a store, once; and a `payment_check` that accepts a `tempo` charge (a transaction or a proof) paid from the agent's wallet and otherwise requires the signature. Both take an optional `allow` callback. Because a Rust server often sees only the request path, the server is configured with the API's public origin, which the signature covers. On the client, `identity::ext::erc8004::client::prover` signs each request with the agent's wallet. `identity::headers::REQUEST` and the proxy now treat `Agent-Id` and `Agent-Signature` as bearer identity headers.
