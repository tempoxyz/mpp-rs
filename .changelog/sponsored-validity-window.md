---
mpp: patch
---

Widen the client's default expiring-nonce `valid_before` window for Tempo charges from 25 to 60 seconds (still capped at the challenge `expires`), and enforce the 15-second remaining-validity floor for fee-sponsored charges at issuance: the client refuses to sign a sponsored challenge that expires in under 15 seconds, and the server refuses to issue a sponsored charge challenge whose `expires` is under 15 seconds away. With the server requiring 15 seconds of remaining validity, a 25-second window left too little room for clock skew between client and server; 60 seconds leaves about 45 seconds for skew, signing and round trips. This deliberately diverges from mppx's 25 seconds. Clients should upgrade alongside servers that require the 15-second floor.
