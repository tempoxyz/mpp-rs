---
mpp: patch
---

Fixed `parse_www_authenticate_all` splitting challenges on `, Payment ` text inside quoted parameter values, which broke valid challenges and let a `Payment` challenge be read out of another scheme's quoted parameter. Scheme detection now also accepts a tab after `Payment`, auth-params accept whitespace around `=`, and a challenge's parameters end at the next auth scheme.
