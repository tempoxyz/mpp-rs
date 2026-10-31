---
mpp: patch
---

Aligned zero-amount Tempo proof credentials with mppx. Access keys (keychain signing mode and Tempo Accounts) now sign a Keychain V2 envelope naming the wallet, byte-identical to viem's. The server rejects a Keychain proof whose envelope names another account.
