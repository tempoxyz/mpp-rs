---
mpp: minor
---

Added `MppError::CredentialReplayed` and `ErrorCode::CredentialReplayed`: replayed Tempo charge credentials (used transaction hashes and proofs, duplicate submissions, settled transfers whose memo is bound to another challenge) are now answered with a `403` `verification-failed` problem and no `WWW-Authenticate` challenge or `challengeId`, so clients do not pay again. A transaction credential whose broadcast or settlement failed releases its submission claim, as in mppx, so resending it retries instead of being rejected as a replay.
