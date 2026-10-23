---
mpp: patch
---

`scrub_response_headers` now strips payment protocol headers an upstream service returns (`Accept-Payment`, `Payment-Authorization`, `Payment-Receipt`, `Payment-Required`, `Payment-Response`, `Payment-Session`, `Payment-Session-Snapshot`, `Payment-Signature`), drops `Authorization` values using the Payment scheme, and removes Payment challenges from `WWW-Authenticate` while keeping other schemes. Proxied requests also strip `Payment-Session` and `Payment-Session-Snapshot`.
