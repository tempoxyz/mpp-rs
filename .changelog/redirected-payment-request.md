---
mpp: minor
---

Rejected automatic payment of a redirected non-GET/HEAD request with `HttpError::RedirectedRequest` before creating a credential, because a 301/302/303 may already have turned it into a GET.
