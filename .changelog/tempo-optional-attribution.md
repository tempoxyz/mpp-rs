---
mpp: patch
---

Changed Tempo charge verification to accept a primary transfer without an attribution memo or with a non-attribution memo, as the Tempo charge spec makes attribution optional; attribution for another challenge or realm now fails as a verification failure (402) instead of a replayed credential. Tempo charge challenges now emit amounts without leading zeros, proof credentials signed by an access key now require AccountKeychain to name that key, and amounts with leading zeros are accepted and compared numerically.
