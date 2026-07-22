---
"mpp": patch
---

Load pending Accounts SDK key authorizations from the shared Tempo Wallet store so native Rust clients can provision a fresh access key with their first transaction. Open a fresh session after access-key rotation instead of trying to reuse a channel bound to the previous voucher signer.
