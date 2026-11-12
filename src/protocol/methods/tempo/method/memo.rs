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
//! an unattributed transfer to the recipient could present it. As for pull,
//! any other attribution memo on a matched push transfer, including another
//! realm's, is rejected: otherwise one transaction whose transfers carry two
//! realms' attribution could pay a challenge at each.

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
/// five bytes are not the MPP tag and version) and the memos of transfers
/// matched to an expected transfer that configures that memo are accepted.
/// `memos` are the memos of all matched transfers, and an expected transfer
/// with a memo only matches a transfer with that memo, so each memo the
/// server configured in `expected` exempts one occurrence of it: a copy of
/// a configured memo on a transfer matched to an unconfigured expected
/// transfer is checked like any other memo.
///
/// A failure is a verification failure (402 with a fresh challenge), as the
/// spec requires, not a replayed credential.
pub(super) fn assert_pull_attribution<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    expected: &[Transfer],
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let mut configured_memos: Vec<&[u8; 32]> = expected
        .iter()
        .filter_map(|transfer| transfer.memo.as_ref())
        .collect();
    for memo in memos {
        let configured = match configured_memos
            .iter()
            .position(|configured| *configured == memo)
        {
            Some(index) => {
                configured_memos.swap_remove(index);
                true
            }
            None => false,
        };
        if !configured
            && attribution::is_mpp_memo(memo)
            && !is_challenge_bound_memo(memo, challenge_id, realm)
        {
            return Err(challenge_bound_memo_error());
        }
    }
    Ok(())
}

/// The attribution check for the matched transfers of a hash (push)
/// credential: [`assert_pull_attribution`], plus at least one memo bound
/// to this challenge and realm.
///
/// A hash credential names a transfer that is already on chain and that the
/// server did not broadcast, so only bound attribution ties it to the
/// challenge it answers. Without it, anyone who saw a plain transfer of the
/// route's amount to the recipient could claim it as their payment.
pub(super) fn assert_hash_credential_attribution<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    expected: &[Transfer],
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let memos: Vec<&[u8; 32]> = memos.into_iter().collect();
    assert_pull_attribution(memos.iter().copied(), expected, challenge_id, realm)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// One transaction whose transfers carry two realms' attribution must
    /// not pay a push challenge at either realm.
    #[test]
    fn hash_attribution_rejects_another_realms_memo() {
        let own = attribution::encode("challenge-a", "a.example", None);
        let other = attribution::encode("challenge-b", "b.example", None);
        assert!(
            assert_hash_credential_attribution([&own], &[], "challenge-a", "a.example").is_ok()
        );
        assert!(assert_hash_credential_attribution(
            [&own, &other],
            &[],
            "challenge-a",
            "a.example"
        )
        .is_err());
        assert!(assert_hash_credential_attribution(
            [&other, &own],
            &[],
            "challenge-b",
            "b.example"
        )
        .is_err());
        assert!(
            assert_hash_credential_attribution([&[0u8; 32]], &[], "challenge-a", "a.example")
                .is_err()
        );
    }

    /// A memo the server configured on one split exempts only the transfer
    /// matched to that split: a copy of it on the primary transfer is
    /// checked like any other attribution memo.
    #[test]
    fn configured_memo_exempts_only_its_own_transfer() {
        let foreign = attribution::encode("challenge-b", "b.example", None);
        let expected = [
            Transfer {
                amount: alloy::primitives::U256::from(90u64),
                recipient: alloy::primitives::Address::repeat_byte(0x33),
                memo: None,
            },
            Transfer {
                amount: alloy::primitives::U256::from(10u64),
                recipient: alloy::primitives::Address::repeat_byte(0x44),
                memo: Some(foreign),
            },
        ];
        assert!(assert_pull_attribution([&foreign], &expected, "challenge-a", "a.example").is_ok());
        assert!(assert_pull_attribution(
            [&foreign, &foreign],
            &expected,
            "challenge-a",
            "a.example"
        )
        .is_err());
        let own = attribution::encode("challenge-a", "a.example", None);
        assert!(
            assert_pull_attribution([&own, &foreign], &expected, "challenge-a", "a.example")
                .is_ok()
        );
        assert!(assert_hash_credential_attribution(
            [&foreign, &foreign, &own],
            &expected,
            "challenge-a",
            "a.example"
        )
        .is_err());
    }
}
