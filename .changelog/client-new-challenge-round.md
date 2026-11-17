---
mpp: patch
---

The HTTP and MCP clients resent the same Credential when the server offered the Challenge it had just answered again, and the MCP client paid a new Challenge offered after a refused Credential, as mppx does. Any MCP answer other than payment required, such as a server error, ended the call without paying again, and adapters report it through the new `ToolCaller::payment_answer_from_error` and `ToolCaller::payment_answer_from_output` hooks. While a `challenge.received` callback that can return a Credential is registered, the previous Credential is rolled back before it runs, so a callback paying through the same session provider is not left waiting on that Credential's lease.
