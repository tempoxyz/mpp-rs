---
mpp: patch
---

Fixed a session `open` for a channel the server already records lowering the recorded deposit when its on-chain read was older than the record, e.g. from a lagging node right after a top-up. The deposit only grows, as it already did for vouchers and top-ups.
