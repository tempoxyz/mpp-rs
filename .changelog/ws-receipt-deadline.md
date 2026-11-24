---
alloy-transport-mpp: patch
---

Fixed `MppWsConnect` waiting indefinitely for a Receipt after paying: it now ends the connection and abandons the payment when the server sends nothing within the handshake timeout of the credential, or no acknowledging Receipt within the handshake timeout of a Receipt that does not acknowledge it. Streams that send the payment's Receipt only at the end keep working.
