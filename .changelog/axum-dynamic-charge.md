---
mpp: patch
---

Added the `MppDynamicCharge` Axum extractor with `DynamicChargeConfig` and `ChargeAmount` for per-request prices; a request without an amount is rejected with 500 and no Challenge. The README's Tempo server quick start now runs as written, documents `MPP_SECRET_KEY`, and is built as the `axum-readme` example.
