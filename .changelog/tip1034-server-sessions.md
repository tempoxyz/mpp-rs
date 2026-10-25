---
mpp: minor
---

Servers verify TIP-1034 channel reserve precompile sessions: when a session's escrow is the precompile, open, voucher, topUp and close credentials must carry a channel descriptor that hashes to the channel id, opens are checked against the descriptor (payer, payee, operator, token, salt, signer, expiringNonceHash), vouchers accept TIP-1020 primitive signatures (so P-256 access keys can pay), state is read with getChannelState, and closes require the cooperative close authorization and capture only what was spent. Legacy escrow sessions are unchanged.
