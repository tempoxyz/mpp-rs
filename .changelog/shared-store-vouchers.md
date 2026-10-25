---
mpp: patch
---

Session payments and prepaid vouchers raise a channel held in process memory to the cumulative amount and deposit recorded in the channel store before signing. When processes share a store, a process that had not used a channel since another process paid with it no longer signs a voucher that the server rejects as not greater than its highest accepted voucher.
