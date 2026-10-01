---
mpp: patch
---

Fixed session channel IDs being matched as raw strings, so a credential that spelled the channel ID with uppercase hex was rejected with `channel-not-found`. The session method, the built-in channel stores and the SSE/WebSocket session helpers now key channels by the lowercase ID.
