---
mpp: minor
---

Added integration tests for the MPP charge flow against a live Tempo blockchain. Introduced an `integration` feature flag, a `docker-compose.yml` for running a local Tempo node, a `test-integration` Makefile target, and `tests/integration_charge.rs` with E2E tests covering health checks, 402 challenge flow, full charge round-trips, auth scheme validation, and balance verification. Added a cross-SDK smoke test CI workflow (`smoke-cross-sdk.yml`) that validates interoperability between the `mpp-rs` server and the `mppx` CLI.
