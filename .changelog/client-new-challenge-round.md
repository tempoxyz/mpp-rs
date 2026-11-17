---
mpp: patch
---

The MCP client paid a new Challenge offered after a refused Credential and resent the same Credential when offered the same Challenge again, as mppx does. Any answer other than payment required, such as a server error, ended the call without paying again, and adapters report it through the new `ToolCaller::payment_answer_from_error` and `ToolCaller::payment_answer_from_output` hooks.
