---
mpp: patch
---

Changed the error for a `402` response with no payable challenge to mppx's wording: `No method found for challenges: <method.intent, ...>. Available: <method.intent, ...>`. A `402` answering a paid retry is still returned as the response.
