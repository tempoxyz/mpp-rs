//! Challenge binding of the attribution memos on matched transfers.

use crate::protocol::traits::VerificationError;
use crate::tempo::attribution;

use super::receipt_logs::MatchedTransferLog;

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

/// Require a challenge-bound attribution memo among the memos of the matched
/// transfers, and reject MPP attribution for any other challenge or server.
///
/// Otherwise one transaction could carry attribution for several challenges
/// and be accepted for each of them. Non-MPP memos are ignored.
pub(super) fn assert_challenge_bound_memos<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let mut bound = false;
    for memo in memos {
        if !attribution::is_mpp_memo(memo) {
            continue;
        }
        if !is_challenge_bound_memo(memo, challenge_id, realm) {
            return Err(challenge_bound_memo_error());
        }
        bound = true;
    }

    if bound {
        Ok(())
    } else {
        Err(challenge_bound_memo_error())
    }
}

pub(super) fn is_challenge_bound_memo(memo: &[u8; 32], challenge_id: &str, realm: &str) -> bool {
    attribution::verify_server(memo, realm)
        && attribution::verify_challenge_binding(memo, challenge_id)
}

pub(super) fn challenge_bound_memo_error() -> VerificationError {
    VerificationError::new("Payment verification failed: memo is not bound to this challenge.")
}
