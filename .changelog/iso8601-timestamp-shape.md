---
mpp: patch
---

Accepted Challenge \`expires\` and Receipt \`timestamp\` values that match mppx's ISO 8601 shape without checking the calendar, so values such as \`2025-02-30T12:00:00Z\` now parse as they do in mppx. Expiry checks still treat an \`expires\` they cannot read as a date as expired.
