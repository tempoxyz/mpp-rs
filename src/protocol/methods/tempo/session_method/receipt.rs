//! Session receipts.

use super::ChannelState;
use crate::protocol::core::Receipt;
use crate::protocol::methods::tempo::session_receipt::SessionReceipt;

/// Build the receipt of a session action from the channel state it left
/// behind. `tx_hash` is the transaction the action settled on-chain, if any.
pub(super) fn session_receipt(
    challenge_id: &str,
    state: &ChannelState,
    tx_hash: Option<String>,
) -> Receipt {
    let mut receipt = channel_receipt(challenge_id, &state.channel_id, state);
    receipt.tx_hash = tx_hash;
    receipt.to_base_receipt()
}

/// Build the session receipt that reports `state`, the current state of the
/// channel `channel_id`.
pub(crate) fn channel_receipt(
    challenge_id: &str,
    channel_id: &str,
    state: &ChannelState,
) -> SessionReceipt {
    let mut receipt = SessionReceipt::new(
        now_iso8601(),
        challenge_id,
        channel_id,
        state.highest_voucher_amount.to_string(),
        state.spent.to_string(),
    );
    receipt.units = Some(state.units);
    receipt
}

pub(super) fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
