---
mpp: patch
---

Changed the identity client to resend a paid request once after a 401, when a prover's `retry` asks to, with refreshed identity and the same Payment credential while its Challenge has not expired, unless the 401 carries a receipt, as mppx does. Paid requests are still never resent after a 403 or any other response.
