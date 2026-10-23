---
mpp: patch
---

Raised the Authorization credential size limit from 16 KiB to 64 KiB, matching mppx, and applied it to the raw header before scheme extraction. A credential echoes its challenge, so credentials for challenges with a `request` near its 16 KiB limit or a large `opaque` were rejected even though mppx accepts them. `extract_payment_scheme` now returns `None` for headers over 64 KiB instead of tokenizing them. Challenge `request` and receipt limits are unchanged.
