---
"mpp": patch
---

Reject malformed human-readable amounts before converting them to base units,
preventing inputs such as `.` from being normalized to zero.
