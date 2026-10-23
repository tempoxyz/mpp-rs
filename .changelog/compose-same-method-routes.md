---
mpp: patch
---

`compose_verify_with_expected_requests` now dispatches a credential to the route whose expected request its challenge was issued for when several routes share a payment method, such as two Tempo handlers with different currencies or recipients, instead of checking it against the first handler for that method.
