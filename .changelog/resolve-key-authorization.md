---
"mpp": patch
---

Resolve persisted Tempo Wallet key authorizations against the Account Keychain before signing. Already-authorized access keys now omit the one-time authorization instead of failing fresh charge or session transactions with `KeyAlreadyExists`.
