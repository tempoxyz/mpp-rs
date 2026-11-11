//! Challenge binding of the attribution memos on matched transfers.
//!
//! Attribution is optional for transaction (pull) credentials and
//! zero-amount proofs: the server broadcasts the client's own signed
//! transaction, so a transfer with no memo, or with a memo that is not in
//! attribution format, is accepted. Hash (push) credentials name a transfer
//! that is already on chain, so they must carry attribution bound to the
//! challenge; otherwise anyone who saw an unattributed transfer to the
//! recipient could present it. An attribution memo of this realm for another
//! challenge is always rejected, so one transaction cannot settle here and
//! later be claimed for that other challenge. Attribution for another realm
//! is accepted on pull credentials; a push credential still needs a memo
//! bound to this challenge and realm.

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

/// Reject any attribution memo of this realm among `memos` that is bound to
/// another challenge. Memos that are not in attribution format (their first
/// five bytes are not the MPP tag and version), attribution for another
/// realm, and no attribution at all are accepted.
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

/// Reject `memo` when it is an attribution memo of this realm bound to
/// another challenge.
///
/// Such a transaction could otherwise settle here and later be presented as
/// a hash credential for that other challenge. Attribution for another realm
/// is another server's business and is accepted, like any non-attribution
/// memo.
pub(super) fn assert_memo_not_foreign(
    memo: &[u8; 32],
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    if attribution::is_mpp_memo(memo)
        && attribution::verify_server(memo, realm)
        && !attribution::verify_challenge_binding(memo, challenge_id)
    {
        return Err(challenge_bound_memo_error());
    }
    Ok(())
}

/// The attribution check for the matched transfers of a hash (push)
/// credential: [`assert_challenge_bound_memos`], plus at least one memo bound
/// to this challenge and realm.
///
/// A hash credential names a transfer that is already on chain and that the
/// server did not broadcast, so only bound attribution ties it to the
/// challenge it answers. Without it, anyone who saw a plain transfer of the
/// route's amount to the recipient could claim it as their payment.
pub(super) fn assert_hash_credential_attribution<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let memos: Vec<&[u8; 32]> = memos.into_iter().collect();
    assert_challenge_bound_memos(memos.iter().copied(), challenge_id, realm)?;
    if !memos
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
