---
mpp: patch
---

Fixed in-band WebSocket vouchers being verified without telling the client the result, so a rejected voucher left the session waiting forever. The new `ws_session::process_vouchers` takes a sink for the socket and answers every credential frame with a `receipt` frame, or with an `error` frame after which it returns the verification error. `process_incoming_vouchers` is deprecated in its favour.
