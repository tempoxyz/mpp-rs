---
mpp: patch
---

Stopped WebSocket reconnects from renewing payment authorization after a charge or voucher attempt. Rejected custom-header payment challenges before credential creation when the caller's reqwest redirect policy cannot be verified, while selecting a safe alternative challenge when offered.
