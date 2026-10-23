---
mpp: patch
---

Recover a Tempo charge whose `eth_sendRawTransactionSync` call returns an RPC error after the node included the transaction: the server now looks up the receipt for the broadcast hash and, if it exists, verifies it like a normal reply instead of failing the paid request. Matches mppx. Recovery runs only when a replay store reserved the submission, so a server without one never re-accepts an already-mined transaction; an unrecovered broadcast releases its reservation so a retry can recover the charge once it lands.
