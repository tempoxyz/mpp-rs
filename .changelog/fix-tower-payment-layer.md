---
mpp: patch
---

Fixed `PaymentLayer::charge` and `PaymentBodyLayer::charge` being unusable from other crates: their return type named a private verifier type, and the layers were not `Clone` for non-`Clone` verifiers, so `axum::Router::layer` and `route_layer` rejected them.
