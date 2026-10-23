---
mpp: minor
---

`sse::ServeOptions` and `ws_session::WsSessionOptions` take a `before_charge` check that runs before each value is charged and delivered, and `SessionMethod::stream_check` provides one that stops the stream when the channel's on-chain escrow has a pending close, was withdrawn, or cannot be read, caching successful reads for five seconds.
