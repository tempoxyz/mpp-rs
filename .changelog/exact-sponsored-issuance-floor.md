---
mpp: patch
---

A fee-sponsored charge challenge must now expire at least 15 seconds after issuance, measured exactly rather than rounded to the nearest second, matching the client's check before signing. A challenge with 14.75 seconds left is refused at issuance instead of being issued and then refused by the client.
