---
mpp: patch
---

Fixed `base64url_decode`, and the header parsers built on it, accepting `=` anywhere but as trailing padding, so a Payment-Receipt or credential such as `=eyJ...` no longer parses, as in mppx.
