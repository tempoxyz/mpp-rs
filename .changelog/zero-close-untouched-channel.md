---
mpp: patch
---

Aligned session close-amount validation with the current mppx session credential verification. The close amount must be `>= spent` and `>= on-chain settled`, so closing at exactly the settled amount is now valid (it captures, it does not replay). A close against a zero on-chain deposit is rejected: it is either an unfunded channel or one already settled to zero, which previously could finalize a channel and return a success receipt without an on-chain close. A close below a nonzero on-chain settled amount remains rejected (CVE-2026-34209 / GHSA-mv9j-8jvg-j8mr), and the captured `max(spent, settled)` must fit within the on-chain deposit.
