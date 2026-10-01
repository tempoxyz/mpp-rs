---
mpp: patch
---

Fixed `PaymentMiddleware` sending the paid retry to the original request URL after a same-origin redirect. The credential now goes to the final URL that issued the challenge, matching `Fetch`.
