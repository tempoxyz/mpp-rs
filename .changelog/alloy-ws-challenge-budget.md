---
alloy-transport-mpp: patch
---

Fixed `MppWsConnect` paying every `challenge` frame a server sent. A connection now pays at most `with_max_payments` challenges (default 3, matching the HTTP client); a challenge beyond the limit closes the connection with a fatal error.
