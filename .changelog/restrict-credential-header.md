---
mpp: patch
---

Fixed the challenge `header` parameter accepting any HTTP field name, which let a server steer the client's credential into headers such as `Cookie` or `Proxy-Authorization`. Only `Payment-Authorization` is accepted now: challenges and credentials advertising any other field are rejected when parsed, clients no longer pay them, and `format_www_authenticate` refuses to emit them. `PaymentChallenge::with_header` and `with_secret_key_full` ignore other values.
