---
mpp: patch
---

Fixed the MCP client stopping after one payment when the server refused the credential and offered a new challenge, such as a zero-amount proof answered by a `credit_insufficient` payment requirement offering only the real charge. Each new challenge is now selected, checked and paid as a new round, up to `DEFAULT_MAX_PAYMENT_RETRIES`, matching mppx's client retry rounds; a challenge already paid, an unpayable offer or a refused payment that already settled ends the call. Added regression tests for this scenario on the HTTP client and middleware, which already handled it.
