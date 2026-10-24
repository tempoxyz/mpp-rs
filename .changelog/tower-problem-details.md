---
mpp: minor
---

Add opt-in RFC 9457 JSON bodies to `PaymentLayer` and `PaymentBodyLayer` with
`with_problem_details`. Applications supply a JSON-bytes-to-body callback while
existing layers retain empty response bodies by default. Payment rejections keep
their status and retry challenge; internal failures return a generic 500 problem
without exposing backend details.
Generated 400 and 413 responses from these layers now carry
`Cache-Control: no-store`, with or without problem details.
Untyped `PaymentVerifier::verify` errors, including those from `from_fns`, are
reported as a generic `verification-failed` problem without the verifier's message.
