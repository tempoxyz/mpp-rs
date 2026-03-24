---
mpp: patch
---

Fixed `base64url_decode` to accept standard base64 (`+`, `/`, `=` padding) in addition to URL-safe base64, following Postel's law and aligning with the mppx TypeScript SDK behavior. Added tests covering standard base64 with padding, URL-safe without padding, and standard alphabet without padding in both `types.rs` and `headers.rs`.
