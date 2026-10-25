---
mpp: patch
---

Signed server session close transactions with an expiring nonce instead of the close signer's sequential nonce, so independent server processes sharing a close signer no longer race for the same nonce.

The pending close records the transaction's `valid_before`, and reconciliation releases a channel whose close is still unmined 30 seconds past it (matching mppx's clock-skew margin), so a close that can no longer land does not leave the channel stuck in `closing`. For TIP-1034 channels it reads the precompile's `getChannelState` at a block past `valid_before` and releases the channel only while it is still funded with no close request, as mppx does; otherwise the channel stays blocked.
