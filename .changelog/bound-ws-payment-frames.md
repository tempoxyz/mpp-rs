---
mpp: patch
---

`ws_session::process_vouchers` now rejects inbound WebSocket frames larger than the new `MAX_INCOMING_MESSAGE_BYTES` (64 KiB) before parsing them: it sends a `payment message is too large` error frame and ends processing with an `InvalidPayload` error. The deprecated `process_incoming_vouchers` skips such a frame unparsed and keeps reading until the connection ends.
