---
mpp: patch
---

Fixed `format_www_authenticate` emitting Latin-1 and control characters raw, which produced header values that clients could not read or that were not valid header values at all. Everything outside printable ASCII is now escaped as `\uXXXX`. Challenges that the parser would reject (empty `id`, invalid method name, `request` that is not base64url JSON) are refused, and `HttpTransport::respond_challenge` returns a 500 response instead of panicking or sending a bare `Payment` challenge when a challenge cannot be formatted.
