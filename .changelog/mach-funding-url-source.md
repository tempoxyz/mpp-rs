---
mpp: patch
---

Fixed `fundingUrl` in problem details to come only from a session insufficient-balance reason, so a MACH funding link echoed in another error's detail, or a client error's link behind a masked internal error, is no longer reported as `fundingUrl`.
