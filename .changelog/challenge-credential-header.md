---
mpp: patch
---

Rejected received challenges and echoed credentials whose `header` auth-param is anything but `Payment-Authorization` in any case (including an explicit `Authorization` or an empty value), skipping such challenges so another challenge in the same response can still be paid, as mppx does. A locally built challenge or echo whose `header` is `Authorization` in any case now serializes without it, as mppx does, and serializing any other unsupported value fails. `mcp::extract_result_challenges` now returns an empty list instead of `None` when every challenge was rejected for its header, so `McpClient` rolls back a paid retry answered that way instead of committing it.
