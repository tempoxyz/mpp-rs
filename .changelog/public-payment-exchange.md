---
mpp: minor
---

Added `send_with_exchange` and made `Exchange` and `FlowError` public, so the HTTP 402 payment flow can run over a host application's HTTP stack instead of a `reqwest::Client`. Request failures keep the exchange's own error type.
