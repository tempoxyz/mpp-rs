---
mpp: minor
---

Fixed the problem types reported for payment failures. Malformed credentials now map to `malformed-credential` (402) instead of `internal-payment-error` or `invalid-challenge`, challenge-binding failures (unknown or tampered challenge id, missing or mismatched bound fields) map to `invalid-challenge` instead of `verification-failed`, and RPC, store and upstream API failures during verification map to `internal-payment-error` (500) instead of `verification-failed` (402). `internal-payment-error` problems now carry a fixed `detail` instead of the underlying error text, and `ErrorCode::spec_code()` returns the problem type that is actually reported.

Migration: `ErrorCode` is now `#[non_exhaustive]` and gained `InvalidChallenge` and `Internal`, and `MppError` gained `Internal` and `InvalidReceipt`, so exhaustive matches need a wildcard arm. `Mpp::verify_*` reports binding failures with `ErrorCode::InvalidChallenge` instead of `ErrorCode::CredentialMismatch`, `parse_authorization` fails with `MppError::MalformedCredential`, and `parse_receipt` fails with `MppError::InvalidReceipt` instead of `MppError::InvalidChallenge`.
