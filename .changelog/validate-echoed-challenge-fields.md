---
mpp: minor
---

Fixed challenge fields being validated differently depending on how they arrived. Challenges parsed from `WWW-Authenticate`, challenges deserialized from JSON (MCP) and the challenge echoed in a credential now go through one validator: `intent` must match the intent grammar and is no longer lowercased by the header parser, `request` must be a base64url JSON object, `opaque` must be base64url, `digest` must be `sha-256=` followed by base64 (optionally wrapped in colons), and `expires` must be RFC 3339. `PaymentChallenge`'s `Deserialize` also rejects an empty `id` and a `header` other than `Payment-Authorization`. With these checks no bound field can contain the `|` that separates the fields in the challenge id input.

Migration: `format_www_authenticate` refuses the same values, so a server using an intent name with characters other than letters, digits, `-` and `_`, or a `request` that is not a JSON object, has to change it.
