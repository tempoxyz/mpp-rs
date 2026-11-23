---
mpp: patch
---

Made `Mpp::create` and `Mpp::create_stripe` reject a realm outside printable ASCII, which a Challenge header can't carry, instead of failing every Challenge at request time.
