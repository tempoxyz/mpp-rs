---
mpp: minor
---

Add `ChargeClient` for explicitly authorized charge payments using either
`Authorization` or `Payment-Authorization`. The SDK owns the HTTP client and
disables redirects for initial requests and paid retries. Session offers are
filtered before provider preparation, and the prepaid-credential hook is skipped.
Existing Fetch, middleware, and session management custom-header restrictions
remain in place.
