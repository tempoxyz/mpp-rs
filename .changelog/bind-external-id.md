---
mpp: patch
---

`verify_credential_with_expected_request` and the other expected-request verifiers now reject a credential whose `externalId` differs from the expected request, so a payment issued for one order cannot settle another order of the same price. Callers that issue challenges with an `external_id` must pass the same value in the expected request.
