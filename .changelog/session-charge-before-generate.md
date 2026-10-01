---
mpp: patch
---

Fixed `sse::serve` and `ws_session` polling the application generator before looking at the channel, which started the first unit of work for channels that were exhausted, closed or missing. The generator is now first polled once the channel can pay for one tick: until then the stream asks for a voucher and waits, and it ends without polling the generator when the channel is closed or missing.
