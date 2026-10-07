---
mpp: patch
---

Reused the signed top-up transaction when retrying a refreshed challenge and enforced the local deposit cap before signing.

Serialized top-ups with channel-store leases, reconciled deposits before enforcing caps, and rejected refreshed challenges that change sponsorship mode.
