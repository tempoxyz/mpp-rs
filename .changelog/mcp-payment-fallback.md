---
mpp: patch
---

`McpPayment::prepare`, `prepare_with_management` and `McpClient::call_tool` pay the next supported challenge in preference order when paying the preferred one fails, and return the first failure only when none can be paid. A wallet that cannot fund a session's suggested deposit, such as Mercator's 5 MACH minimum, now pays the server's one-time charge instead of failing the call.
