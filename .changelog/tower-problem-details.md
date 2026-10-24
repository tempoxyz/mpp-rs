---
mpp: minor
---

Add opt-in RFC 9457 JSON bodies to `PaymentLayer` and `PaymentBodyLayer` with
`with_problem_details`. Applications supply a JSON-bytes-to-body callback while
existing layers retain empty response bodies by default. Payment rejections keep
their status and retry challenge; internal failures return a generic 500 problem
without exposing backend details.
