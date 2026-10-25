---
mpp: patch
---

Enforce the 15-second remaining-validity floor for fee-sponsored charges at issuance: the client refuses to sign a sponsored challenge that expires in under 15 seconds, and the server refuses to issue a sponsored charge challenge whose `expires` is under 15 seconds away (zero-amount proof charges are exempt, since nothing is co-signed). The client's default expiring-nonce `valid_before` window stays at 25 seconds, matching mppx and Tempo's 30-second expiring-nonce maximum. A sponsor `max_validity_window_seconds` below 15 seconds is now rejected as misconfigured, and the window is counted from the current time rounded up, as in mppx.
