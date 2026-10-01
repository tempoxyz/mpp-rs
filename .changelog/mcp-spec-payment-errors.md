---
mpp: patch
---

Fixed MCP payment errors to match the JSON-RPC transport spec and mppx: challenges are serialized with `request` as a native JSON object instead of a base64url string, verification failures use `-32043` (which `is_payment_required` now accepts), and one malformed challenge no longer discards the valid alternatives. `attach_credential` and `attach_receipt` no longer panic on non-object input; the new `try_attach_credential` and `try_attach_receipt` report the failure.
