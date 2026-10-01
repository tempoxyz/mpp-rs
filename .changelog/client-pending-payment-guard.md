---
mpp: patch
---

Added `mpp::client::PendingPayment`, the guard that commits, rolls back or abandons a created credential. It was only available as `mpp::mcp::client::PendingPayment`, which is now a re-export, and gained `new` and `invalidate`.
