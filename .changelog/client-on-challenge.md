---
mpp: patch
---

Changed `Fetch`, `PaymentMiddleware` and `ChargeClient` to pay a 402 without a request-level `Accept-Payment` header by default (`AcceptPaymentPolicy::Always`), as mppx does; `AcceptPaymentPolicy::Explicit` stays selectable, including through the new `ChargeClient::with_accept_payment_policy`. Added an `on_challenge` approval hook (`ClientEvents::set_on_challenge`, `PaymentMiddleware::with_on_challenge`, `ChargeClient::with_on_challenge`) that approves, declines (returning the 402 unpaid) or supplies a credential before each payment, as mppx's `onChallenge` does, and `Fetch` and `PaymentMiddleware` now send the credential in `Payment-Authorization` when a challenge asks for it instead of refusing to pay, and a 402 answering a credential with `invalid-challenge` (the replay answer) was returned without paying again.
