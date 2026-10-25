---
mpp: patch
---

Serialized session top-ups per payment scope, including background top-ups, and rechecked the deposit after waiting so concurrent requests through one provider no longer fund a channel twice or past `max_deposit`. A wait for another top-up ends when the challenge expires, and a background top-up's `channel.deposit` event reports only its own increase.
