---
mpp: patch
---

Background session top-ups hold the payment lock and store lease only while the top-up is signed and recorded, not while it is submitted, so vouchers for concurrent requests are not delayed. Recording a top-up raises the current channel entry's deposit instead of writing back the entry it was signed against.
