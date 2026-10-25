---
mpp: minor
---

`sse::ServeOptions` and `ws_session::WsSessionOptions` take a `before_charge` check that runs before each value is charged and delivered, and `SessionMethod::stream_check` provides one that stops the stream when the channel's on-chain escrow has a pending close, was withdrawn, or cannot be read, caching successful reads for five seconds and counting amounts settled on chain above the highest accepted voucher as spent (settling an accepted voucher keeps its unspent credit). The check runs once per value, not on every poll while the stream waits for a voucher.
