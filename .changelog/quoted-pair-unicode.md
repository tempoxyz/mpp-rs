---
mpp: patch
---

Fixed `WWW-Authenticate` parsing to read a backslash escape as an RFC 9110 quoted-pair, so `\u2014` is the text `u2014` instead of a decoded character. Formatting now rejects characters outside printable ASCII in every auth-param but `description`, which still escapes them as `\uXXXX` so the Challenge can always be sent, as mppx does.
