---
mpp: patch
---

Serialized session top-ups, including background top-ups, and rechecked the deposit after waiting so concurrent requests no longer fund a channel twice or past `max_deposit`.
