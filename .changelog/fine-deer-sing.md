---
mpp: minor
---

Added integration tests for the MPP charge flow against a live Tempo blockchain. Introduced an `integration` feature flag, updated dev dependencies (`axum`, `reqwest`, `hex`, tokio `net` feature), added a `test-integration` Makefile target, and added `tests/integration_charge.rs` with E2E tests covering health checks, 402 challenge flow, full charge round-trips, and auth scheme validation.
