---
mpp: minor
---

`PaymentMiddleware` now reports payment failures as `HttpError`, the error `Fetch` returns, inside `reqwest_middleware::Error::Middleware`. They used to be ad-hoc `anyhow` messages that callers could not match on. Code that downcast the middleware error to `MppError` should downcast to `HttpError` and match `HttpError::Payment`. The messages, including the `error` text of `payment.failed` events, now use the `HttpError` wording.
