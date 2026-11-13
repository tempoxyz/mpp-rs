---
mpp: patch
---

Changed Tempo transaction (pull) credentials to look up the signed transaction's receipt right before broadcasting and reject one that is already on chain with `verification-failed`, as mppx does, so a transaction another server or an earlier settlement already settled is never counted again; recovery after a failed broadcast now only accepts a transaction that was still pending at that check. Challenge expiry is checked again right before the broadcast, so a challenge that expires during these checks is no longer broadcast.
