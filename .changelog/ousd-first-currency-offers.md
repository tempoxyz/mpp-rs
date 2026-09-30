---
mpp: minor
---

Offer OUSD first in Tempo server currency defaults. Servers on Tempo mainnet now accept OUSD, then USDC.e, and servers on Moderato accept OUSD, then pathUSD, issuing one charge challenge per accepted currency, whether or not fee sponsorship is enabled; omitted chains resolve from the configured RPC URL (mainnet by default), and unknown chains keep the single pathUSD default. Add an ordered `TempoBuilder::currencies` option that replaces the defaults (validated, deduplicated case-insensitively, and rejected when empty or combined with the now-deprecated single `currency` option), `Mpp::currencies`, `Mpp::charge*` helpers returning `Vec<PaymentChallenge>` (including for a single accepted currency), and multi-offer 402 responses in the Axum extractors and Tower layer. Credentials and session vouchers for any accepted currency verify, so existing channels opened in the previous default keep working.

Decouple the sponsored fee token from the charge currency, matching mppx. A local fee payer pays gas in the configured `fee_payer_fee_token`, otherwise the first allowlisted fee token it holds a nonzero balance of, otherwise the first allowlisted token. The default fee-token allowlist is now pathUSD plus the chain's default currency (mainnet: pathUSD and USDC.e; Moderato: pathUSD), so sponsored OUSD charges pay gas in pathUSD or USDC.e. OUSD is not a default fee token.

The built-in HTTP transport selects the first valid Payment offer across comma-joined or repeated WWW-Authenticate headers.
