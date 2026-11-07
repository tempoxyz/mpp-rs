---
mpp: patch
---

Fixed Zone payments to check again that the challenge leaves time to settle right before sending the withdrawal, to treat a send receipt for another transaction hash or a `WithdrawalRequested` event that doesn't match the signed withdrawal as an unknown outcome, and fixed hash credentials to reject a transaction that settled Zone withdrawals, so one settlement can't pay for both a hash credential and Zone credentials.
