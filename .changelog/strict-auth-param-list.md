---
mpp: patch
---

Fixed `parse_www_authenticate` and `parse_www_authenticate_all` to reject a Challenge with text right after a quoted value, a word after its last auth-param with no comma before it, or an empty unquoted value, as mppx does.
