---
alloy-transport-mpp: patch
---

Fixed `MppWsConnect` waiting indefinitely for a Receipt after paying: a payment that no Receipt acknowledges within the handshake timeout of its credential being sent now ends the connection and abandons the payment. Receipts that do not acknowledge the payment do not extend that wait.
