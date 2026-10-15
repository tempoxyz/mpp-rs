---
mpp: patch
---

Fixed automatic session management to preserve the configured HTTP client and strip hop-by-hop request headers. Middleware callers can provide the same client with `with_http_client`; automatic top-ups are disabled when it is absent.
