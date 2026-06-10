---
mpp: minor
---

Validate the credential `source` on the Tempo hash-credential verification path. The server now parses the `did:pkh:eip155` source before reserving the transaction hash, requires TIP-20 transfers to originate from the declared source address (falling back to the receipt sender when no source is provided), and rejects malformed or chain-mismatched sources with a uniform error. Adds `ChargeMethod::with_validate_sender` to authorize smart-account / relayer flows where the on-chain transfer sender differs from the declared source.
