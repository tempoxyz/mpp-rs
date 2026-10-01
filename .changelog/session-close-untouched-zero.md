---
mpp: patch
---

Fixed session `close` rejecting a zero-amount close of a channel that was opened but never used, which left the deposit locked until a forced close. A funded channel with nothing spent and nothing settled on-chain can now be closed at `0`, refunding the payer. A close at or below a non-zero settled amount, or above the deposit, is still rejected.
