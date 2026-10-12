---
mpp: patch
---

Limited autoswaps to the missing balance and bounded input spending independently of quotes. Added an optional max_amount_in budget, defaulting to parity plus slippage. Sponsored validation accepts positive swap outputs up to the payment amount. Existing AutoswapConfig struct literals must add max_amount_in: None; the constructor remains unchanged.
