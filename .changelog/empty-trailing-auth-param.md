---
mpp: patch
---

Fixed `parse_www_authenticate` dropping an empty unquoted auth-param at the end of a header (`description=`). It is now kept as an empty value, as it already was when followed by a comma, and as mppx does.
