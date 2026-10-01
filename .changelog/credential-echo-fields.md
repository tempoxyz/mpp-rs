---
mpp: minor
---

Fixed the credential's challenge echo dropping `description`, and credentials whose echoed `opaque` uses the legacy object form sent by older mppx clients being rejected. `ChallengeEcho` has a new `description` field that `PaymentChallenge::to_echo` fills in, and an object-shaped `opaque` is normalized to its base64url string. Code that builds `ChallengeEcho` with a struct literal must add `description: None` (or use `to_echo`).
