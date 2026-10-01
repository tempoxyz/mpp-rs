---
mpp: patch
---

Fixed SSE `message` events for values containing line breaks: the value was truncated at the first newline while still being charged, and streamed content could inject `payment-need-voucher` or `payment-receipt` events. `format_message_event` now emits one `data:` line per line, and `parse_event` accepts CRLF/CR line endings and `data:` fields without a space after the colon.
