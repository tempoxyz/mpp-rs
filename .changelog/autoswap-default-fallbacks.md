---
mpp: minor
---

Added default fallback currencies to Tempo autoswap, as mppx does: the swap tries `AutoswapConfig::token_in` first, then pathUSD, USDC.e and OUSD (`DEFAULT_AUTOSWAP_CURRENCIES`, skipping duplicates and the challenge currency), and uses the first one the payer holds with a DEX route within the spend limit. `AutoswapConfig::default()` swaps from the defaults alone with 1% slippage, like mppx's `autoSwap: true`. `AutoswapConfig::new` now falls back by default; the new `fallback` field (`with_fallback(false)`) restricts swaps to `token_in`, as mppx's `autoSwap.fallback: false`. Struct literals must now set `fallback`. Added `resolve_autoswap_route`, which also returns the chosen input token, and `AutoswapConfig::with_max_amount_in`. Charges pay gas in the swap's input token, and OUSD, which cannot pay fees, is never used as the autoswap fee token.
