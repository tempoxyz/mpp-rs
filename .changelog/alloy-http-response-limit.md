---
alloy-transport-mpp: patch
---

Fixed `MppHttpTransport` buffering JSON-RPC response bodies of any size, which let an RPC endpoint exhaust the client's memory. Responses larger than 256 MiB now fail with a transport error; the limit is configurable with `with_max_response_bytes`.
