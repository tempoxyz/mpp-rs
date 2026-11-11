---
mpp: patch
---

Changed Tempo charge verification of transaction credentials to accept a primary transfer without an attribution memo, with a non-attribution memo or with another realm's attribution memo, since the server broadcasts the client's own transaction; hash credentials still require attribution bound to the challenge and realm, so a transfer someone else made cannot be claimed. This realm's attribution for another challenge, or a hash credential without bound attribution, now fails as a verification failure (402) instead of a replayed credential. A settled transaction's hash is recorded in the same replay record hash credentials are checked against. Tempo charge challenges now emit amounts without leading zeros, proof credentials signed by an access key now require AccountKeychain to name that key, and amounts with leading zeros are accepted and compared numerically.
