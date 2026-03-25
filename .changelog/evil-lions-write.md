---
mpp: patch
---

Fixed channel state updates to correctly propagate `settled_on_chain` and `spent` values when a channel is reopened, ensuring `spent` is bumped to at least the on-chain settled amount to prevent double-spending.
