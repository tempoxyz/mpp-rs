---
mpp: patch
---

Fixed Receipt parsing to reject an explicit `null` `externalId` or `subscriptionId` instead of reading it as absent, as mppx does.
