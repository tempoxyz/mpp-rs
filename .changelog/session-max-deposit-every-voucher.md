---
mpp: minor
---

Fixed `TempoSessionProvider` enforcing `max_deposit` only when a voucher needed a top-up. A channel whose deposit is above the limit, e.g. one opened with a higher limit, restored from the channel store or recovered from the server, was spent up to its full deposit. Every voucher signed by `pay` is now checked, so such a payment fails with `exceeds local max_deposit`; raise `with_max_deposit` to keep spending from that channel.
