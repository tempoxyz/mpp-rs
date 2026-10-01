---
mpp: patch
---

Fixed body-bound payment front-ends buffering request bodies of any size before payment. The axum `MppChargeWithBody` extractor now honours `DefaultBodyLimit` (2 MiB unless configured), and the tower `PaymentBodyLayer` caps the body at 2 MiB, configurable with `max_body_bytes`. Oversized bodies are rejected with 413, and body read errors in `MppChargeWithBody` now return 400 instead of 500.
