---
mpp: patch
---

Fixed `Fetch` and `PaymentMiddleware` failing with `NoSupportedChallenge` when a paid request was answered with a 402 whose challenges the provider cannot pay. That response is now returned like a 402 without a challenge, as mppx does, so the caller can read its problem details. An unpayable first 402 is still an error.
