---
mpay: minor
---

Added stream intent support for streaming/metered payments via payment channels, including credential payload types (open, topUp, voucher, close), EIP-712 voucher signature verification, server-side channel state management with monotonicity enforcement, and tokio dependency for concurrent storage operations.
