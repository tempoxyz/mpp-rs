---
mpp: patch
---

Fixed the `WWW-Authenticate` parsers to reject a Challenge with text right after a quoted value, a word after its last auth-param with no comma before it, or an empty unquoted value, as mppx does.
