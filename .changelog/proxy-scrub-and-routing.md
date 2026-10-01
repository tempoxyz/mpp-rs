---
mpp: patch
---

Fixed the proxy helpers forwarding the client's `Payment-Authorization` credential to the upstream service; `scrub_request_headers` now strips it like `Authorization`. Fixed `ProxyConfig::match_route` letting a `:param` segment match `.`, `..` (also `%2e`-encoded) or a segment containing a backslash, which reached other upstream paths once the forwarding client normalised the URL, and `base_path` matching without a segment boundary (`/api` matched `/apiopenai/...`).
