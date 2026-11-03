---
mpp: patch
---

Fixed building against tempo-primitives from T14 on, where a keychain signature's approval became an `AccountSignature`: sponsored-transaction simulation now reads the approval's key type and WebAuthn data independently of that type, and rejects a configurable account sender signature instead of failing to compile.
