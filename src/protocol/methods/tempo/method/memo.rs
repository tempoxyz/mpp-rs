//! Challenge binding of the attribution memos on matched transfers.
//!
//! Attribution is optional for transaction (pull) credentials and
//! zero-amount proofs: the server broadcasts the client's own signed
//! transaction, so a transfer with no memo, or with a memo that is not in
//! attribution format, is accepted. Any attribution memo on a pull
//! credential must be bound to this challenge and realm, though: a pull
//! settled here carrying another realm's or another challenge's attribution
//! could later be presented to that server as a hash credential, and its
//! replay store has no record of the settlement. Memos the server configures
//! (`methodDetails.memo`, split memos) are matched exactly and exempt.
//!
//! Hash (push) credentials name a transfer that is already on chain, so they
//! must carry attribution bound to the challenge; otherwise anyone who saw
//! an unattributed transfer to the recipient could present it. Attribution
//! of this realm for another challenge on a push credential is rejected;
//! attribution for another realm on one of its other transfers is accepted.

use crate::protocol::traits::VerificationError;
use crate::tempo::attribution;

use super::super::transfers::Transfer;
use super::receipt_logs::MatchedTransferLog;

/// The attribution check for the matched transfers of a settled pull
/// receipt: [`assert_pull_attribution`] over the memos of `matched_logs`.
pub(super) fn assert_pull_attribution_logs(
    matched_logs: &[MatchedTransferLog],
    expected: &[Transfer],
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let memos = matched_logs.iter().filter_map(|log| match log {
        MatchedTransferLog::Transfer => None,
        MatchedTransferLog::Memo(memo) => Some(memo),
    });
    assert_pull_attribution(memos, expected, challenge_id, realm)
}

/// The attribution check for the matched transfers of a transaction (pull)
/// credential: reject any attribution memo that is not bound to this
/// challenge and realm, including another realm's attribution.
///
/// Plain transfers, memos that are not in attribution format (their first
/// five bytes are not the MPP tag and version) and memos equal to one the
/// server configured in `expected` are accepted.
///
/// A failure is a verification failure (402 with a fresh challenge), as the
/// spec requires, not a replayed credential.
pub(super) fn assert_pull_attribution<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    expected: &[Transfer],
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    for memo in memos {
        let configured = expected
            .iter()
            .any(|transfer| transfer.memo.as_ref() == Some(memo));
        if !configured
            && attribution::is_mpp_memo(memo)
            && !is_challenge_bound_memo(memo, challenge_id, realm)
        {
            return Err(challenge_bound_memo_error());
        }
    }
    Ok(())
}

/// Reject any attribution memo of this realm among `memos` that is bound to
/// another challenge. Memos that are not in attribution format, attribution
/// for another realm, and no attribution at all are accepted.
fn assert_challenge_bound_memos<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    for memo in memos {
        if attribution::verify_server(memo, realm)
            && !attribution::verify_challenge_binding(memo, challenge_id)
        {
            return Err(challenge_bound_memo_error());
        }
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
