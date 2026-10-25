---
mpp: patch
---

An MCP payment management call that the server definitively rejects (a JSON-RPC payment error such as -32042 or -32043) now fails as a rejection rather than as an unknown outcome, so a refused top-up no longer blocks later top-ups on that channel.
