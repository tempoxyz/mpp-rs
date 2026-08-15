---
mpp: minor
---

Add separate non-mutating charge validation and terminal broadcast APIs, retaining verification as a compatibility alias and falling back to legacy method implementations. Add `TempoRelayConfig` and `TempoBuilder::relay` for delegating Tempo charge credential validation and finalization to Tempo API or a compatible MPP relay. Relay requests normalize the echoed challenge request, derive deterministic broadcast idempotency keys, validate returned receipts, and hide private relay failures. Add an Axum charge-relay example dogfooded against Tempo Moderato.
