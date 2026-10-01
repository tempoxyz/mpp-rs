---
mpp: patch
---

Fixed the proxy's OpenAPI discovery document describing paths clients cannot call. `generate_openapi` now prefixes paths with the configured `base_path`, writes `:param` route segments as `{param}` templates with matching path `parameters`, and emits `x-payment-info` in the multi-offer form (`{"offers": [...]}`) the discovery spec recommends instead of the flat single-offer shorthand.
