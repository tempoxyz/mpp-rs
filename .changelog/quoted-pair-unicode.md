---
mpp: patch
---

Fixed `WWW-Authenticate` parsing to read a backslash escape as an RFC 9110 quoted-pair (`\u2014` is the text `u2014`), and formatting now rejects characters outside printable ASCII in every auth-param but `description`, which still escapes them as `\uXXXX`, as mppx does. Clients now skip, before paying, a Challenge whose server escaped a parameter it binds or echoes (any recognized one but `description`) as `\uXXXX`, and fail with "Legacy unicode-escaped challenge" when no other Challenge remains (see `parse_payable_challenges`).
