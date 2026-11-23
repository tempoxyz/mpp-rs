---
mpp: minor
---

`parse_authorization` now reads only `Payment <base64url-json>`, as mppx's `Credential.deserialize` does: pass an `Authorization` value that lists other schemes through `extract_payment_scheme` first. Challenge parsing now requires a comma between auth-params, and RFC 9110 tokens for parameter names and unquoted values.
