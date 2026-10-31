---
mpp: patch
---

Added hosted fee payers configured on the server, as mppx's `feePayer: url | { url, headers }`: `TempoBuilder::fee_payer_url` and `TempoBuilder::remote_fee_payer(TempoRemoteFeePayer::new(url).with_header(..))`, and `ChargeMethod::with_remote_fee_payer`. The service co-signs over `eth_fillTransaction`; only its `feePayerSignature` and `feeToken` are used (checked against an explicit fee-token allowlist when set), the sponsor is recovered from its signature, and the server simulates and broadcasts the transaction itself.
