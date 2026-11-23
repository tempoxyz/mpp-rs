---
mpp: patch
---

`base64url_decode`, and the header parsers built on it, now reject `=` anywhere but as trailing padding, so a Payment-Receipt or credential such as `=eyJ...` fails to parse, as in mppx.
