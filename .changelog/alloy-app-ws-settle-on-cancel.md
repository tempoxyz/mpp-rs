---
alloy-transport-mpp: patch
---

Fixed `MppApplicationWsConnect::connect` leaving the initial payment unsettled when the handshake timed out or the future was dropped after paying. The payment is now abandoned in those cases, so a `TempoSessionProvider` no longer keeps its payment lock and blocks every later payment.
