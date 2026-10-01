//! The metering loop behind the SSE and WebSocket session helpers.

use super::sse::NeedVoucherEvent;
use crate::protocol::methods::tempo::session_method::{
    channel_receipt, deduct_from_channel, ChannelState, ChannelStore,
};
use crate::protocol::methods::tempo::session_receipt::SessionReceipt;
use crate::protocol::traits::ErrorCode;

/// What a metered session sends to its client next.
pub(super) enum MeteredEvent {
    /// A generated value that has been charged for.
    Message(String),
    /// The channel cannot pay for the next value. Emitted once per
    /// exhaustion: clients answer every one of them with a voucher.
    NeedVoucher(NeedVoucherEvent),
    /// The final receipt. Nothing follows it.
    Receipt(SessionReceipt),
}

/// A stream of generated values that are charged against a channel.
pub(super) struct Metered<'a, G> {
    pub(super) store: &'a dyn ChannelStore,
    /// Lowercase channel ID.
    pub(super) channel_id: &'a str,
    pub(super) challenge_id: &'a str,
    /// Cost per generated value in base units.
    pub(super) tick_cost: u128,
    pub(super) generate: G,
    pub(super) poll_interval_ms: u64,
    pub(super) min_voucher_delta: u128,
}

impl<'a, G> Metered<'a, G>
where
    G: futures_core::Stream<Item = String> + Send + Unpin + 'a,
{
    /// Run the session: charge `tick_cost` for every value of `generate`,
    /// asking for a voucher and waiting while the channel cannot pay, and end
    /// with the final receipt if the channel is readable.
    pub(super) fn events(self) -> impl futures_core::Stream<Item = MeteredEvent> + Send + 'a {
        let Metered {
            store,
            channel_id,
            challenge_id,
            tick_cost,
            generate,
            poll_interval_ms,
            min_voucher_delta,
        } = self;

        async_stream::stream! {
            let mut stream = std::pin::pin!(generate);

            // Hold the generator back until the channel can pay for the first value,
            // so that no work is started for an exhausted, closed or missing channel.
            let mut need_voucher_sent = false;
            loop {
                let Ok(Some(ch)) = store.get_channel(channel_id).await else {
                    return;
                };
                if ch.finalized || ch.closing {
                    yield MeteredEvent::Receipt(channel_receipt(challenge_id, channel_id, &ch));
                    return;
                }
                if ch.highest_voucher_amount.saturating_sub(ch.spent) >= tick_cost {
                    break;
                }
                if !need_voucher_sent {
                    need_voucher_sent = true;
                    yield MeteredEvent::NeedVoucher(need_voucher(
                        channel_id,
                        &ch,
                        tick_cost,
                        min_voucher_delta,
                    ));
                }
                wait_for_update(store, channel_id, poll_interval_ms).await;
            }

            while let Some(value) = next_item(&mut stream).await {
                // Try to charge, waiting for top-up if insufficient
                let mut need_voucher_sent = false;
                loop {
                    match deduct_from_channel(store, channel_id, tick_cost).await {
                        Ok(_state) => break,
                        Err(e) if e.code == Some(ErrorCode::InsufficientBalance) => {
                            // Ask once per exhaustion: clients answer every need-voucher
                            // event, so a repeat makes them sign a duplicate voucher.
                            if !need_voucher_sent {
                                if let Ok(Some(ch)) = store.get_channel(channel_id).await {
                                    need_voucher_sent = true;
                                    yield MeteredEvent::NeedVoucher(need_voucher(
                                        channel_id,
                                        &ch,
                                        tick_cost,
                                        min_voucher_delta,
                                    ));
                                }
                            }
                            wait_for_update(store, channel_id, poll_interval_ms).await;
                        }
                        Err(_) => {
                            // Closed, missing, or unreadable channel — no voucher can fix
                            // that, so emit the final receipt and stop.
                            if let Some(receipt) = final_receipt(store, channel_id, challenge_id).await {
                                yield MeteredEvent::Receipt(receipt);
                            }
                            return;
                        }
                    }
                }

                yield MeteredEvent::Message(value);
            }

            if let Some(receipt) = final_receipt(store, channel_id, challenge_id).await {
                yield MeteredEvent::Receipt(receipt);
            }
        }
    }
}

/// The receipt for the channel's current state, if the channel is readable.
pub(super) async fn final_receipt(
    store: &dyn ChannelStore,
    channel_id: &str,
    challenge_id: &str,
) -> Option<SessionReceipt> {
    let channel = store.get_channel(channel_id).await.ok()??;
    Some(channel_receipt(challenge_id, channel_id, &channel))
}

fn need_voucher(
    channel_id: &str,
    channel: &ChannelState,
    tick_cost: u128,
    min_voucher_delta: u128,
) -> NeedVoucherEvent {
    NeedVoucherEvent {
        channel_id: channel_id.to_string(),
        required_cumulative: required_cumulative(channel, tick_cost, min_voucher_delta).to_string(),
        accepted_cumulative: channel.highest_voucher_amount.to_string(),
        deposit: channel.deposit.to_string(),
    }
}

/// Cumulative amount a need-voucher event asks for: enough to pay for the
/// next tick, and at least `min_voucher_delta` above the accepted amount.
fn required_cumulative(channel: &ChannelState, tick_cost: u128, min_voucher_delta: u128) -> u128 {
    let next_tick = channel.spent.saturating_add(tick_cost);
    let min_accepted = channel
        .highest_voucher_amount
        .saturating_add(min_voucher_delta);
    next_tick.max(min_accepted)
}

/// Wait for the channel to change, or for the poll interval when the store
/// cannot tell.
async fn wait_for_update(store: &dyn ChannelStore, channel_id: &str, poll_interval_ms: u64) {
    tokio::select! {
        _ = store.wait_for_update(channel_id) => {},
        _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)) => {},
    }
}

/// Poll the next item from a stream (avoids depending on StreamExt).
pub(super) async fn next_item<S: futures_core::Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    use std::future::poll_fn;
    use std::pin::Pin;

    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}
