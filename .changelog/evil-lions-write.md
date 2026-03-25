---
mpp: patch
---

Reject deductions on finalized channels: `deduct_from_channel` now checks `state.finalized` before allowing a spend, returning `ChannelClosed` error. SSE streaming treats finalized/closed channels as terminal instead of retrying indefinitely. Also fixed channel state updates to correctly propagate `settled_on_chain` and `spent` values when a channel is reopened, ensuring `spent` is bumped to at least the on-chain settled amount to prevent double-spending.
