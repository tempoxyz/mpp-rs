---
mpp: patch
---

Fixed the Tempo charge client signing a fee-sponsored transaction whose `valid_before` had fewer than 15 seconds left after slow preparation: the pre-sign check now measures `valid_before` as well as the challenge expiry.
