---
mpp: patch
---

Challenge and credential headers are now read by one tokenizer, so `parse_www_authenticate`, `parse_www_authenticate_all`, `extract_payment_scheme` and `PaymentProtocol::detect` agree on where a `Payment` scheme starts. An auth-param named `Payment` no longer splits a challenge in the list parser, `extract_payment_scheme` ignores text inside quoted-strings, empty list elements before a challenge are skipped by every parser, and only ASCII whitespace is skipped around the scheme.
