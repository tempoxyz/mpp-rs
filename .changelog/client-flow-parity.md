---
mpp: patch
---

Fixed `PaymentMiddleware` and `Fetch` answering the same 402 differently. The middleware now calls the provider's `prepare_http_payment_challenge` hook, reopens a stale session once after `410 Gone` instead of returning the 410, and returns a 402 that carries no challenge after a payment instead of failing. `Fetch` now repeats `Accept-Payment` on retries and sends requests whose body cannot be cloned, failing with `HttpError::CloneFailed` only when such a request is answered with a 402; a request builder that holds an error reports that error instead of `CloneFailed`. A session that is still gone after the retry is invalidated again rather than rolled back.
