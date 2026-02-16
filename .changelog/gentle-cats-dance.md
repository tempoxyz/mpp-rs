---
mpp: patch
---

Mandated JCS (RFC 8785) for canonical JSON serialization of request parameters by replacing `serde_json::to_string` with `serde_json_canonicalizer::to_string` throughout the protocol layer.
