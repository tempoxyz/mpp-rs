---
mpp: minor
---

Rejected automatic payment of a redirected non-GET/HEAD request with `HttpError::RedirectedRequest` before creating a credential, because a 301/302/303 may already have turned it into a GET. Transports report redirects through the new `Exchange::redirected` (default: the response URL differs), so ones that record redirect history also catch same-URL redirects, and `PaymentMiddleware::with_redirects_disabled` keeps paying requests whose URL inner middleware rewrites.
