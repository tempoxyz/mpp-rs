use super::*;

/// An on-chain read can be older than the recorded state, so it never
/// lowers the deposit, the settled amount or `spent`.
#[test]
fn test_refresh_on_chain_keeps_the_higher_values() {
    let mut state = test_channel_state("0xchannel");
    state.deposit = 100_000;
    state.settled_on_chain = 3_000;
    state.spent = 2_000;

    let stale = state
        .clone()
        .refresh_on_chain(&on_chain_channel(&state, 50_000, 1_000));
    assert_eq!(stale.deposit, 100_000);
    assert_eq!(stale.settled_on_chain, 3_000);
    assert_eq!(stale.spent, 3_000);

    let newer = state
        .clone()
        .refresh_on_chain(&on_chain_channel(&state, 150_000, 4_000));
    assert_eq!(newer.deposit, 150_000);
    assert_eq!(newer.settled_on_chain, 4_000);
    assert_eq!(newer.spent, 4_000);
}

#[test]
fn test_pending_close_is_marked_once_and_cleared() {
    let mut state = test_channel_state("0xchannel");
    state.spent = 500;

    let closing = state.clone().mark_pending_close(500).unwrap();
    assert!(closing.closing);
    for refused in [
        closing.clone(),
        ChannelState {
            finalized: true,
            ..state.clone()
        },
    ] {
        let err = refused.mark_pending_close(500).unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::ChannelClosed));
    }

    assert!(!closing.clear_pending_close().closing);
    // A channel that was finalized in the meantime is left as it is.
    let finalized = ChannelState {
        finalized: true,
        closing: true,
        ..state
    };
    assert!(finalized.clear_pending_close().closing);
}

/// The stored voucher is what the server can still settle with, so a close
/// below it must not replace it.
#[test]
fn test_finalize_close_keeps_the_highest_voucher() {
    let mut state = test_channel_state("0xchannel");
    state.highest_voucher_amount = 1_000;
    state.highest_voucher_signature = Some(vec![0xAA; 65]);
    state.closing = true;

    let below = state.clone().finalize_close(400, vec![0xBB; 65], 100_000);
    assert!(below.finalized && !below.closing);
    assert_eq!(below.highest_voucher_amount, 1_000);
    assert_eq!(below.highest_voucher_signature, Some(vec![0xAA; 65]));

    let above = state.finalize_close(2_000, vec![0xBB; 65], 100_000);
    assert!(above.finalized && !above.closing);
    assert_eq!(above.highest_voucher_amount, 2_000);
    assert_eq!(above.highest_voucher_signature, Some(vec![0xBB; 65]));
}

mod properties {
    use super::*;
    use crate::protocol::methods::tempo::session_method::state::Opening;
    use proptest::prelude::*;

    /// A transition a handler applies to the recorded channel.
    #[derive(Debug, Clone)]
    enum Step {
        /// `open` for the channel that is already recorded.
        Reopen {
            deposit: u128,
            settled: u128,
            cumulative: u128,
        },
        /// An on-chain read, possibly older than the record.
        Refresh {
            deposit: u128,
            settled: u128,
        },
        Voucher {
            amount: u128,
            min_delta: u128,
        },
        Deduct {
            amount: u128,
        },
        MarkPendingClose {
            amount: u128,
        },
        ClearPendingClose,
        FinalizeClose {
            amount: u128,
            deposit: u128,
        },
    }

    // Amounts stay in a small range so that steps collide with each other.
    const AMOUNT: std::ops::Range<u128> = 0..2_000;

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            1 => (AMOUNT, AMOUNT, AMOUNT).prop_map(|(deposit, settled, cumulative)| Step::Reopen {
                deposit,
                settled,
                cumulative
            }),
            2 => (AMOUNT, AMOUNT).prop_map(|(deposit, settled)| Step::Refresh { deposit, settled }),
            4 => (AMOUNT, 0..200u128).prop_map(|(amount, min_delta)| Step::Voucher {
                amount,
                min_delta
            }),
            6 => (0..300u128).prop_map(|amount| Step::Deduct { amount }),
            1 => AMOUNT.prop_map(|amount| Step::MarkPendingClose { amount }),
            1 => Just(Step::ClearPendingClose),
            1 => (AMOUNT, AMOUNT).prop_map(|(amount, deposit)| Step::FinalizeClose {
                amount,
                deposit
            }),
        ]
    }

    fn opening(state: &ChannelState, cumulative_amount: u128) -> Opening {
        Opening {
            channel_id: state.channel_id.clone(),
            chain_id: state.chain_id,
            escrow_contract: state.escrow_contract,
            authorized_signer: state.authorized_signer,
            settlement_route: None,
            cumulative_amount,
            signature: vec![0xAA; 65],
        }
    }

    /// Apply `step` the way its handler does: a refused transition leaves the
    /// record as it was.
    fn apply(state: &ChannelState, step: &Step) -> Result<ChannelState, VerificationError> {
        let state = state.clone();
        match *step {
            Step::Reopen {
                deposit,
                settled,
                cumulative,
            } => {
                let on_chain = on_chain_channel(&state, deposit, settled);
                let opening = opening(&state, cumulative);
                Ok(ChannelState::open(Some(state), &on_chain, opening))
            }
            Step::Refresh { deposit, settled } => {
                let on_chain = on_chain_channel(&state, deposit, settled);
                Ok(state.refresh_on_chain(&on_chain))
            }
            Step::Voucher { amount, min_delta } => {
                state.accept_voucher(amount, vec![0xBB; 65], min_delta)
            }
            Step::Deduct { amount } => state.deduct(amount),
            Step::MarkPendingClose { amount } => state.mark_pending_close(amount),
            Step::ClearPendingClose => Ok(state.clear_pending_close()),
            Step::FinalizeClose { amount, deposit } => {
                Ok(state.finalize_close(amount, vec![0xCC; 65], deposit))
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// Whatever order the handlers run in, the amounts the server may
        /// claim only move forward and a closed channel stays closed.
        #[test]
        fn transitions_keep_the_channel_accounting_sound(
            deposit in AMOUNT,
            settled in AMOUNT,
            cumulative in AMOUNT,
            steps in prop::collection::vec(step(), 1..48),
        ) {
            let template = test_channel_state("0xchannel");
            let on_chain = on_chain_channel(&template, deposit, settled);
            let mut state = ChannelState::open(None, &on_chain, opening(&template, cumulative));
            prop_assert_eq!(state.spent, settled);
            prop_assert_eq!(state.highest_voucher_amount, cumulative);

            for step in &steps {
                let before = state.clone();
                let Ok(after) = apply(&before, step) else {
                    continue;
                };

                // What has been charged, settled or authorized is never taken back.
                prop_assert!(after.spent >= before.spent, "{step:?}");
                prop_assert!(after.settled_on_chain >= before.settled_on_chain, "{step:?}");
                prop_assert!(
                    after.highest_voucher_amount >= before.highest_voucher_amount,
                    "{step:?}"
                );
                prop_assert!(after.units >= before.units, "{step:?}");
                // Everything settled on-chain counts as spent.
                prop_assert!(after.spent >= after.settled_on_chain, "{step:?}");
                // A finalized channel is never reopened.
                prop_assert!(after.finalized || !before.finalized, "{step:?}");

                match *step {
                    Step::Deduct { amount } => {
                        prop_assert!(!before.finalized && !before.closing);
                        prop_assert_eq!(after.spent, before.spent + amount);
                        prop_assert_eq!(after.units, before.units + 1);
                        // Only authorized funds are charged.
                        let authorized = before.highest_voucher_amount.saturating_sub(before.spent);
                        prop_assert!(amount <= authorized);
                    }
                    Step::Voucher { amount, min_delta } => {
                        prop_assert_eq!(after.highest_voucher_amount, amount);
                        prop_assert!(amount > before.highest_voucher_amount);
                        prop_assert!(amount - before.highest_voucher_amount >= min_delta);
                        prop_assert_eq!(after.spent, before.spent);
                    }
                    Step::Refresh { .. } => {
                        prop_assert!(after.deposit >= before.deposit);
                        prop_assert_eq!(after.highest_voucher_amount, before.highest_voucher_amount);
                    }
                    Step::MarkPendingClose { amount } => {
                        prop_assert!(!before.finalized && !before.closing);
                        prop_assert!(after.closing);
                        prop_assert!(amount >= before.spent);
                    }
                    Step::ClearPendingClose => {
                        prop_assert_eq!(after.closing, before.finalized && before.closing);
                    }
                    Step::FinalizeClose { amount, .. } => {
                        prop_assert!(after.finalized && !after.closing);
                        prop_assert_eq!(
                            after.highest_voucher_amount,
                            before.highest_voucher_amount.max(amount)
                        );
                        prop_assert_eq!(after.spent, before.spent);
                    }
                    Step::Reopen { cumulative, .. } => {
                        prop_assert_eq!(
                            after.highest_voucher_amount,
                            before.highest_voucher_amount.max(cumulative)
                        );
                    }
                }

                // A channel that is closing or closed takes no more charges.
                if after.finalized || after.closing {
                    prop_assert!(after.clone().deduct(1).is_err(), "{step:?}");
                    prop_assert!(after.clone().mark_pending_close(u128::MAX).is_err(), "{step:?}");
                }

                state = after;
            }
        }
    }
}
