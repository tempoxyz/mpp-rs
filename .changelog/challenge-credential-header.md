---
mpp: patch
---

Rejected received challenges and echoed credentials whose `header` auth-param is anything but `Payment-Authorization` in any case (including an explicit `Authorization` or an empty value), skipping such challenges so another challenge in the same response can still be paid, as mppx does. Added `mcp::extract_result_payment_challenges` so MCP adapters can treat a result whose challenges were all rejected for their header as offering no supported challenge.
