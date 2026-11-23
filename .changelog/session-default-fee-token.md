---
mpp: patch
---

Added `TempoSessionProvider::with_default_fee_token` and `TempoAccountsProvider::with_session_default_fee_token`, a gas token for unsponsored session opens and top-ups that ranks below an explicit fee token, the server's advertised `feeToken` and the input token of an actual autoswap, and above the session currency. A wallet holding exactly the deposit can now pay gas in another token, such as pathUSD, instead of coming up short.
