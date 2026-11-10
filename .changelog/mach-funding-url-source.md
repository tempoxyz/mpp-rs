---
mpp: patch
---

Fixed `fundingUrl` in problem details to come only from a Tempo client error's typed link or a session insufficient-balance detail, so a MACH funding link echoed in another error's detail is no longer reported as `fundingUrl`.
