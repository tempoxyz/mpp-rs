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
