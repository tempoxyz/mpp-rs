---
mpp: minor
---

Bound each `TempoSessionProvider` to the HTTP origin of its first paid request and persisted that origin with stored channels, as mppx does: requests, SSE vouchers, close and top-up requests, WebSocket recovery and `preconnect` hints for another origin, stored channels bound to another origin and paid session responses redirected to another origin are now refused. Requests carrying a `Payment-Session` channel hint no longer follow redirects. Payments whose context URL is not HTTP, such as MCP resources, leave the provider unbound. `TempoAccountsProvider` keeps one session provider per origin, as mppx keeps a session manager per origin, so one wallet pays several services; `session_for` returns a service's provider. Stored channels without an origin stay usable and take one on their next reuse.
