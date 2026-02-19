---
mpp: minor
---

Added comprehensive integration and unit test coverage across client fetch, client middleware, MCP payment roundtrip, server middleware, server HMAC challenge verification, and SSE metered streaming flows. Also added a `feature-matrix` CI job to validate all feature flag combinations, and introduced `Mpp::new_with_config` test helper and made `detect_realm` pub(crate).
