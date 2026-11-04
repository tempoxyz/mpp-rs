---
mpp: patch
---

Prevented SQLite channel-ID conflicts from overwriting another origin's session. Preserved signed opening recovery state after ambiguous WebSocket delivery failures. Added `MppError::PaymentOutcomeUnknown { transaction_hash }` for ambiguous push broadcasts and stopped MCP offer fallback after that outcome so callers can reconcile the original transaction before retrying.

Preserved same-origin recovery of legacy SQLite rows, replayed pending opening transactions after uncertain delivery, and prevented MCP offer fallback after ambiguous session management operations.
