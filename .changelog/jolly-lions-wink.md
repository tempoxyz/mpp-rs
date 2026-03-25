---
mpp: patch
---

Fixed `close_requested_at` persistence in `ChannelState` by adding the field to the struct with `#[serde(default)]`, propagating it through channel open/reopen logic, and passing the stored value when verifying vouchers. Also fixed `deduct_from_channel` to reject finalized channels early.
