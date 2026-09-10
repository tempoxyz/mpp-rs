---
mpp: patch
---

Fixed WWW-Authenticate quoted-string parsing to preserve non-ASCII text. Values were built one byte at a time as if each byte were a character, so `café` parsed as `cafÃ©`, and the `\uXXXX` escapes a challenge uses for characters above Latin-1 were decoded as the literal text `u2014` rather than `—`. Surrogate pairs are recombined, and an unpaired surrogate decodes to U+FFFD.
