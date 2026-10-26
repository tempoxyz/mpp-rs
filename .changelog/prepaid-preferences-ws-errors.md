---
mpp: patch
---

Honor request Accept-Payment preferences before creating prepaid Tempo session vouchers and defensively validate cached challenges before transmission. Custom prepaid providers must check request preferences before signing or reserving authorization.

Sanitize internal WebSocket voucher errors using the same typed conversion as HTTP responses, while retaining the original error for server diagnostics.
