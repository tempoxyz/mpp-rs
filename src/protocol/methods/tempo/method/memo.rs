//! Challenge binding of the attribution memos on matched transfers.
//!
//! The Tempo charge spec makes the attribution memo optional: a client should
//! put one on the primary transfer, but a server must not require it. A
//! transfer with no memo, or with a memo that is not in attribution format, is
//! accepted. An attribution memo for another challenge or realm is rejected,
//! so one transaction cannot carry attribution for several challenges and be
//! accepted for each of them.

use crate::protocol::traits::VerificationError;
use crate::tempo::attribution;

use super::receipt_logs::MatchedTransferLog;

/// Reject attribution for another challenge among the matched transfers of a
/// settled receipt; plain transfers and non-attribution memos are accepted.
pub(super) fn assert_challenge_bound_memo(
    matched_logs: &[MatchedTransferLog],
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let memos = matched_logs.iter().filter_map(|log| match log {
        MatchedTransferLog::Transfer => None,
        MatchedTransferLog::Memo(memo) => Some(memo),
    });
    assert_challenge_bound_memos(memos, challenge_id, realm)
}

/// Reject any attribution memo among `memos` that is not bound to this
/// challenge and realm. Memos that are not in attribution format (their first
/// five bytes are not the MPP tag and version) are ignored, and no
/// attribution at all is accepted.
///
/// A failure is a verification failure (402 with a fresh challenge), as the
/// spec requires, not a replayed credential.
pub(super) fn assert_challenge_bound_memos<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    for memo in memos {
        assert_memo_not_foreign(memo, challenge_id, realm)?;
    }
    Ok(())
}

/// Reject `memo` when it is in attribution format but bound to another
/// challenge or realm.
pub(super) fn assert_memo_not_foreign(
    memo: &[u8; 32],
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    if attribution::is_mpp_memo(memo) && !is_challenge_bound_memo(memo, challenge_id, realm) {
        return Err(challenge_bound_memo_error());
    }
    Ok(())
}

/// Whether a hash (push) credential's transfer must carry attribution bound
/// to this challenge.
///
/// Off, as the Tempo charge spec makes attribution optional. A hash
/// credential names a transfer that is already on chain, so without bound
/// attribution anyone who sees an unattributed transfer to the recipient can
/// present it; set this to `true` to require attribution for hash
/// credentials only.
pub(super) const HASH_CREDENTIAL_REQUIRES_ATTRIBUTION: bool = false;

/// The attribution check for the matched transfers of a hash credential:
/// [`assert_challenge_bound_memos`], plus, when
/// [`HASH_CREDENTIAL_REQUIRES_ATTRIBUTION`] is on, at least one memo bound
/// to this challenge.
pub(super) fn assert_hash_credential_attribution<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let memos: Vec<&[u8; 32]> = memos.into_iter().collect();
    assert_challenge_bound_memos(memos.iter().copied(), challenge_id, realm)?;
    if HASH_CREDENTIAL_REQUIRES_ATTRIBUTION
        && !memos
            .iter()
            .any(|memo| is_challenge_bound_memo(memo, challenge_id, realm))
    {
        return Err(challenge_bound_memo_error());
    }
    Ok(())
}

pub(super) fn is_challenge_bound_memo(memo: &[u8; 32], challenge_id: &str, realm: &str) -> bool {
    attribution::verify_server(memo, realm)
        && attribution::verify_challenge_binding(memo, challenge_id)
}

pub(super) fn challenge_bound_memo_error() -> VerificationError {
    VerificationError::new("Payment verification failed: memo is not bound to this challenge.")
}
