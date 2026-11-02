---
mpp: minor
---

Bound each `TempoSessionProvider` to the HTTP origin of its first paid request and persisted that origin with stored channels, as mppx does: requests, SSE vouchers, WebSocket recovery and `preconnect` hints for another origin, non-HTTP URLs, stored channels bound to another origin and paid session responses redirected to another origin are now refused. Stored channels without an origin stay usable and take one on their next reuse.
