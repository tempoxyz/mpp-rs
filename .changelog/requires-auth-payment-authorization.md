---
"mpp": patch
---

Added a `requires_auth` server option that advertises `header="Payment-Authorization"` so Payment credentials do not collide with ordinary `Authorization`.
